// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell supervisor-middleware request adapter.
//!
//! The adapter owns only OpenShell wire translation. Policy evaluation and
//! effect application stay in `apf-policy-eval`, so every enforcement point
//! shares the same decision and mutation semantics.

use std::fmt;
use std::sync::Arc;

use tracing::{debug, info};

use apf_policy_eval::{
    EvalInput, EvalResult, Evaluator, Finding as EvalFinding, HeaderAction,
    HeaderMutation as EvalHeaderMutation, RequestTarget, Severity, Verdict, apply_effects,
};
use prost::Message;
use serde::Deserialize;
use serde_json::{Map, Value};
use tonic::{Request, Response, Status};

use apf_openshell_auth::{
    Authenticated, AuthenticatedCaller, AuthenticationMode, AuthorizationFailure,
    ExtensionAuthVerifier, ExtensionCallerKind,
};
use apf_proto::supervisor_middleware_v1::{
    self as wire, supervisor_middleware_server::SupervisorMiddleware,
    supervisor_middleware_server::SupervisorMiddlewareServer,
};

const SERVICE_NAME: &str = "apf-content-policy";
const HEADER_WRITE_PREFIX: &str = "x-openshell-middleware-";
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REASON_BYTES: usize = 4 * 1024;
const MAX_HEADER_MUTATION_DATA_BYTES: usize = 32 * 1024;
const MAX_HEADER_MUTATION_WIRE_BYTES: usize = 64 * 1024;
const MAX_FINDINGS_PER_STAGE: usize = 32;
const MAX_FINDING_BYTES: usize = 4 * 1024;
const MAX_HEADER_MUTATIONS: usize = 64;
// OpenShell V1 reserves 299,072 bytes above the 4 MiB body limit for the
// bounded request or response envelope.
const GRPC_MESSAGE_BYTES: usize = 4_493_376;

const CODE_BODY_TOO_LARGE: &str = "body_too_large";
const CODE_EFFECT_APPLICATION_FAILED: &str = "effect_application_failed";
const CODE_EVALUATION_FAILED: &str = "evaluation_failed";
const CODE_INVALID_FINDINGS: &str = "invalid_findings";
const CODE_INVALID_CONFIG: &str = "invalid_config";
const CODE_INVALID_HEADER_MUTATION: &str = "invalid_header_mutation";
const CODE_INVALID_MCP_REQUEST: &str = "invalid_mcp_request";
const CODE_INVALID_PHASE: &str = "invalid_phase";
const CODE_MISSING_TARGET: &str = "missing_target";
const CODE_POLICY_DENIED: &str = "policy_denied";
const CODE_REPLACEMENT_BODY_TOO_LARGE: &str = "replacement_body_too_large";

/// Evaluator-backed implementation of OpenShell's supervisor middleware.
///
/// Bundle loading, evaluator refresh, TLS listener startup, and
/// `network_middlewares` registration belong to the policy gateway.
#[derive(Clone)]
pub struct SupervisorMiddlewareService {
    evaluator: tokio::sync::watch::Receiver<Arc<dyn Evaluator>>,
    authentication: AuthenticationMode,
}

/// Size-limited supervisor middleware server protected by extension JWT authentication.
pub type AuthenticatedSupervisorMiddlewareServer =
    Authenticated<SupervisorMiddlewareServer<SupervisorMiddlewareService>>;

impl SupervisorMiddlewareService {
    /// Builds a size-limited server that authenticates every OpenShell call before dispatch.
    #[must_use]
    pub fn authenticated_server(
        evaluator: tokio::sync::watch::Receiver<Arc<dyn Evaluator>>,
        verifier: ExtensionAuthVerifier,
    ) -> AuthenticatedSupervisorMiddlewareServer {
        let service = Self {
            evaluator,
            authentication: AuthenticationMode::Required {
                expected_audience: verifier.audience().to_string(),
            },
        };
        Authenticated::new(service.into_size_limited_server(), verifier)
    }

    /// Builds a size-limited server with authentication deliberately disabled.
    ///
    /// This mode is only for a matching OpenShell registration whose
    /// `allow_insecure_transport` setting explicitly opts out of extension authentication.
    #[must_use]
    pub fn insecure_server(
        evaluator: tokio::sync::watch::Receiver<Arc<dyn Evaluator>>,
    ) -> SupervisorMiddlewareServer<Self> {
        Self {
            evaluator,
            authentication: AuthenticationMode::Insecure,
        }
        .into_size_limited_server()
    }

    fn into_size_limited_server(self) -> SupervisorMiddlewareServer<Self> {
        SupervisorMiddlewareServer::new(self)
            .max_decoding_message_size(GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(GRPC_MESSAGE_BYTES)
    }
}

impl fmt::Debug for SupervisorMiddlewareService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisorMiddlewareService")
            .finish_non_exhaustive()
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for SupervisorMiddlewareService {
    async fn describe(
        &self,
        request: Request<()>,
    ) -> Result<Response<wire::MiddlewareManifest>, Status> {
        self.authentication
            .authorize(
                &request,
                &[
                    ExtensionCallerKind::Gateway,
                    ExtensionCallerKind::Supervisor,
                ],
            )
            .map_err(AuthorizationFailure::into_status)?;
        Ok(Response::new(wire::MiddlewareManifest {
            name: SERVICE_NAME.to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings: vec![wire::MiddlewareBinding {
                operation: wire::SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: wire::SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_BODY_BYTES as u64,
                // An empty binding timeout inherits the operator-owned
                // deadline instead of silently shortening it.
                timeout: String::new(),
            }],
            expected_audience: self.authentication.expected_audience().to_string(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<wire::ValidateConfigRequest>,
    ) -> Result<Response<wire::ValidateConfigResponse>, Status> {
        self.authentication
            .authorize(&request, &[ExtensionCallerKind::Gateway])
            .map_err(AuthorizationFailure::into_status)?;
        let field_count = request
            .into_inner()
            .config
            .map_or(0, |config| config.fields.len());
        let valid = field_count == 0;
        let reason = if valid {
            String::new()
        } else {
            // Values may contain policy or identity data. Report only the
            // shape error so validation never reflects configuration content.
            format!("configuration must be empty; received {field_count} field(s)")
        };
        Ok(Response::new(wire::ValidateConfigResponse {
            valid,
            reason,
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<wire::HttpRequestEvaluation>,
    ) -> Result<Response<wire::HttpRequestResult>, Status> {
        let authenticated_sandbox = self
            .authentication
            .authorize(&request, &[ExtensionCallerKind::Supervisor])
            .map_err(AuthorizationFailure::into_status)?
            .and_then(AuthenticatedCaller::sandbox_id)
            .map(str::to_owned);
        let evaluation = request.into_inner();
        if authenticated_sandbox.is_some_and(|sandbox_id| {
            evaluation
                .context
                .as_ref()
                .is_none_or(|context| context.sandbox_id != sandbox_id)
        }) {
            // A valid supervisor token is scoped to exactly one sandbox. Bind
            // that identity before parsing request content or invoking policy.
            return Err(Status::permission_denied(
                "OpenShell supervisor sandbox does not match the request context",
            ));
        }
        let service = self.clone();
        let response = tokio::task::spawn_blocking(move || service.evaluate(&evaluation))
            .await
            .unwrap_or_else(|_| {
                // A panic or runtime shutdown in the blocking task must not
                // escape as a gRPC failure that OpenShell could fail open.
                deny(CODE_EVALUATION_FAILED, "policy evaluation failed")
            });
        Ok(Response::new(response))
    }

    type EvaluateWebSocketSessionStream = std::pin::Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<
                    Item = Result<wire::WebSocketSessionEventResult, Status>,
                > + Send,
        >,
    >;

    /// APF's manifest never advertises a `WEBSOCKET_MESSAGE` binding
    /// (`describe()` above only binds `HttpRequest`/`PreCredentials`), so
    /// OpenShell never dispatches to this RPC — it exists only to satisfy the
    /// `SupervisorMiddleware` trait. Mirrors the unsupported default OpenShell's
    /// own `InProcessMiddleware::open_websocket_session` documents for
    /// HTTP-only implementations.
    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<wire::WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "apf-content-policy does not inspect WebSocket sessions",
        ))
    }
}

impl SupervisorMiddlewareService {
    fn evaluate(&self, evaluation: &wire::HttpRequestEvaluation) -> wire::HttpRequestResult {
        let sandbox_id = evaluation
            .context
            .as_ref()
            .map_or("", |c| c.sandbox_id.as_str());
        let (host, method, path) = evaluation.target.as_ref().map_or(("", "", ""), |t| {
            (t.host.as_str(), t.method.as_str(), t.path.as_str())
        });
        debug!(
            sandbox_id,
            host, method, path, "middleware: evaluating request"
        );

        if evaluation.phase != wire::SupervisorMiddlewarePhase::PreCredentials as i32 {
            return deny(CODE_INVALID_PHASE, "unsupported middleware phase");
        }
        if evaluation
            .config
            .as_ref()
            .is_some_and(|config| !config.fields.is_empty())
        {
            return deny(
                CODE_INVALID_CONFIG,
                "middleware configuration must be empty",
            );
        }
        if evaluation.body.len() > MAX_BODY_BYTES {
            return deny(CODE_BODY_TOO_LARGE, "request body exceeds middleware limit");
        }

        let body_json = match serde_json::from_slice::<Value>(&evaluation.body) {
            Ok(value) => Some(value),
            Err(_) if contains_mcp_tool_call_intent(&evaluation.body) => {
                // A malformed body that still identifies tools/call cannot
                // shed its tool identity and fall through to generic policy.
                return deny(CODE_INVALID_MCP_REQUEST, "invalid MCP tools/call request");
            }
            Err(_) => None,
        };
        let input = match build_eval_input(evaluation, body_json.as_ref()) {
            Ok(input) => input,
            Err(error) => return deny(error.reason_code(), error.reason()),
        };

        let evaluator = Arc::clone(&*self.evaluator.borrow());
        let Ok(result) = evaluator.evaluate(input) else {
            // Evaluator errors are intentionally not reflected: backend error
            // text is not a stable or audit-safe wire contract.
            return deny(CODE_EVALUATION_FAILED, "policy evaluation failed");
        };

        if !result.allow {
            info!(
                sandbox_id,
                host,
                method,
                path,
                reason = %result.deny_reason,
                "middleware: DENY"
            );
            return policy_deny(&result);
        }

        let Ok(applied) = apply_effects(&evaluation.body, body_json.as_ref(), &result) else {
            // Forwarding an unmodified request would drop a mandated effect,
            // so every application error is a hard deny.
            return deny(
                CODE_EFFECT_APPLICATION_FAILED,
                "policy effects could not be applied",
            );
        };
        if applied
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_BODY_BYTES)
        {
            return deny(
                CODE_REPLACEMENT_BODY_TOO_LARGE,
                "policy replacement body exceeds middleware limit",
            );
        }

        let Ok(header_mutations) = map_header_mutations(&applied.headers) else {
            return deny(
                CODE_INVALID_HEADER_MUTATION,
                "policy produced an invalid header mutation",
            );
        };
        let Ok(findings) = map_findings(&result, true) else {
            return deny(CODE_INVALID_FINDINGS, "policy produced invalid findings");
        };

        let (body, has_body) = applied
            .body
            .map_or_else(|| (Vec::new(), false), |replacement| (replacement, true));

        let finding_labels: Vec<&str> = result.findings.iter().map(|f| f.label.as_str()).collect();
        if finding_labels.is_empty() {
            info!(sandbox_id, host, method, path, "middleware: ALLOW");
        } else {
            info!(
                sandbox_id,
                host,
                method,
                path,
                findings = %finding_labels.join(", "),
                body_mutated = has_body,
                "middleware: ALLOW with findings"
            );
        }

        wire::HttpRequestResult {
            decision: wire::Decision::Allow as i32,
            body,
            has_body,
            header_mutations,
            findings,
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestAdapterError {
    InvalidMcpRequest,
    MissingTarget,
}

impl RequestAdapterError {
    const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidMcpRequest => CODE_INVALID_MCP_REQUEST,
            Self::MissingTarget => CODE_MISSING_TARGET,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::InvalidMcpRequest => "invalid MCP tools/call request",
            Self::MissingTarget => "HTTP request target is missing",
        }
    }
}

fn build_eval_input(
    evaluation: &wire::HttpRequestEvaluation,
    body_json: Option<&Value>,
) -> Result<EvalInput, RequestAdapterError> {
    let target = evaluation
        .target
        .as_ref()
        .ok_or(RequestAdapterError::MissingTarget)?;
    let (tool, args) = parse_tool_call(body_json)?;
    // A lossy view keeps decodable content visible to text detectors even
    // when an otherwise binary body contains invalid UTF-8 bytes.
    let body_text = String::from_utf8_lossy(&evaluation.body).into_owned();

    Ok(EvalInput {
        has_tool_name: tool.is_some(),
        tool,
        capability: None,
        // OpenShell V1 does not carry an authenticated user subject. Keep the
        // absence explicit; sandbox_id must not be misrepresented as a human
        // identity, and subject-sensitive policy must reject an empty value.
        user_subject: String::new(),
        args,
        body_text,
        body_json: body_json.cloned(),
        target: Some(RequestTarget {
            host: target.host.clone(),
            method: target.method.clone(),
            path: target.path.clone(),
            scheme: target.scheme.clone(),
        }),
    })
}

fn parse_tool_call(
    body_json: Option<&Value>,
) -> Result<(Option<String>, Map<String, Value>), RequestAdapterError> {
    let object = match body_json {
        Some(Value::Object(object)) => object,
        Some(Value::Array(items)) if items.iter().any(contains_tool_call_value) => {
            // JSON-RPC can represent batches, but one EvalInput can carry only
            // one canonical identity. Deny tool-call batches from older or
            // custom peers until every call can be evaluated independently.
            return Err(RequestAdapterError::InvalidMcpRequest);
        }
        _ => return Ok((None, Map::new())),
    };
    if object.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok((None, Map::new()));
    }

    // Once an envelope declares tools/call it cannot degrade to protocol-
    // neutral evaluation: malformed tool identity is a hard deny.
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or(RequestAdapterError::InvalidMcpRequest)?;
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or(RequestAdapterError::InvalidMcpRequest)?
        .to_string();
    let args = match params.get("arguments") {
        Some(arguments) => arguments
            .as_object()
            .cloned()
            .ok_or(RequestAdapterError::InvalidMcpRequest)?,
        // MCP permits tools without arguments; an omitted field is the same
        // canonical input as an explicitly empty object.
        None => Map::new(),
    };
    Ok((Some(tool_name), args))
}

fn contains_mcp_tool_call_intent(body: &[u8]) -> bool {
    const TOOL_CALL_MARKER: &[u8] = b"tools/call";
    const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

    let candidate = body.strip_prefix(UTF8_BOM).unwrap_or(body);
    let json_like = candidate
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'['));
    if !json_like {
        // Arbitrary HTTP bodies remain protocol-neutral. MCP uses JSON, so a
        // peer accepting leading non-JSON data is outside this adapter's wire
        // contract and must not make plain text containing a marker look MCP.
        return false;
    }

    if candidate
        .windows(TOOL_CALL_MARKER.len())
        .any(|window| window == TOOL_CALL_MARKER)
    {
        return true;
    }

    // `serde_json::from_slice` rejects a valid value followed by trailing
    // bytes. Decode only the first value here so escaped method spellings in
    // that malformed envelope are still recognized and denied.
    let mut deserializer = serde_json::Deserializer::from_slice(candidate);
    Value::deserialize(&mut deserializer).is_ok_and(|value| contains_tool_call_value(&value))
}

fn contains_tool_call_value(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.get("method").and_then(Value::as_str) == Some("tools/call"),
        Value::Array(items) => items.iter().any(contains_tool_call_value),
        _ => false,
    }
}

fn policy_deny(result: &EvalResult) -> wire::HttpRequestResult {
    let Ok(findings) = map_findings(result, false) else {
        return deny(CODE_INVALID_FINDINGS, "policy produced invalid findings");
    };
    wire::HttpRequestResult {
        decision: wire::Decision::Deny as i32,
        reason: bounded_reason(result.deny_reason.clone()),
        reason_code: CODE_POLICY_DENIED.to_string(),
        findings,
        ..Default::default()
    }
}

fn deny(reason_code: &'static str, reason: &'static str) -> wire::HttpRequestResult {
    wire::HttpRequestResult {
        decision: wire::Decision::Deny as i32,
        reason: reason.to_string(),
        reason_code: reason_code.to_string(),
        ..Default::default()
    }
}

fn bounded_reason(mut reason: String) -> String {
    if reason.len() <= MAX_REASON_BYTES {
        return reason;
    }
    let mut end = MAX_REASON_BYTES;
    // The wire limit is bytes, while truncating a String must retain a UTF-8
    // boundary. Walk back at most three bytes for a valid boundary.
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.truncate(end);
    reason
}

fn map_header_mutations(mutations: &[EvalHeaderMutation]) -> Result<Vec<wire::HeaderMutation>, ()> {
    if mutations.len() > MAX_HEADER_MUTATIONS {
        return Err(());
    }
    let mut data_bytes = 0usize;
    let mut mapped = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        data_bytes = data_bytes
            .saturating_add(mutation.name.len())
            .saturating_add(mutation.value.as_ref().map_or(0, String::len));
        if data_bytes > MAX_HEADER_MUTATION_DATA_BYTES {
            return Err(());
        }
        mapped.push(map_header_mutation(mutation)?);
    }
    let wire_bytes = mapped.iter().fold(0usize, |total, mutation| {
        total.saturating_add(mutation.encoded_len())
    });
    if wire_bytes > MAX_HEADER_MUTATION_WIRE_BYTES {
        return Err(());
    }
    Ok(mapped)
}

fn map_header_mutation(mutation: &EvalHeaderMutation) -> Result<wire::HeaderMutation, ()> {
    if !is_valid_header_name(&mutation.name) {
        return Err(());
    }
    let operation = match mutation.action {
        HeaderAction::Set | HeaderAction::Add => {
            if !has_header_write_prefix(&mutation.name) {
                return Err(());
            }
            let value = mutation.value.clone().ok_or(())?;
            if !is_valid_header_value(&value) {
                return Err(());
            }
            let on_existing = match mutation.action {
                HeaderAction::Set => wire::ExistingHeaderAction::Overwrite,
                HeaderAction::Add => wire::ExistingHeaderAction::Append,
                HeaderAction::Remove => return Err(()),
            };
            wire::header_mutation::Operation::Write(wire::WriteHeader {
                name: mutation.name.clone(),
                value,
                on_existing: on_existing as i32,
            })
        }
        HeaderAction::Remove => {
            if is_protected_header_name(&mutation.name) {
                return Err(());
            }
            wire::header_mutation::Operation::Remove(wire::RemoveHeader {
                name: mutation.name.clone(),
            })
        }
    };
    Ok(wire::HeaderMutation {
        operation: Some(operation),
    })
}

fn has_header_write_prefix(name: &str) -> bool {
    name.get(..HEADER_WRITE_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(HEADER_WRITE_PREFIX))
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_protected_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "cookie"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
    ) || lower.starts_with("x-amz-")
        || lower.starts_with("x-openshell-credential")
}

fn is_valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
}

fn map_findings(
    result: &EvalResult,
    include_advisory_verdict: bool,
) -> Result<Vec<wire::Finding>, ()> {
    let verdict_finding_count =
        usize::from(include_advisory_verdict && result.verdict != Verdict::Allow);
    if result.findings.len() + verdict_finding_count > MAX_FINDINGS_PER_STAGE {
        return Err(());
    }
    let mut findings = Vec::with_capacity(result.findings.len() + verdict_finding_count);
    findings.extend(result.findings.iter().map(map_finding));
    if include_advisory_verdict && let Some(finding) = verdict_finding(result.verdict) {
        findings.push(finding);
    }
    if findings
        .iter()
        .any(|finding| finding.encoded_len() > MAX_FINDING_BYTES)
    {
        return Err(());
    }
    Ok(findings)
}

fn map_finding(finding: &EvalFinding) -> wire::Finding {
    wire::Finding {
        r#type: finding.kind.clone(),
        label: finding.label.clone(),
        count: 1,
        confidence: finding
            .confidence
            .map_or_else(String::new, |value| value.to_string()),
        severity: severity_name(finding.severity).to_string(),
    }
}

const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn verdict_finding(verdict: Verdict) -> Option<wire::Finding> {
    let (label, severity) = match verdict {
        Verdict::Allow => return None,
        Verdict::Warn => ("warn", "medium"),
        Verdict::Escalate => ("escalate", "high"),
    };
    Some(wire::Finding {
        r#type: "policy_verdict".to_string(),
        label: label.to_string(),
        count: 1,
        confidence: String::new(),
        severity: severity.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use apf_policy_eval::{EvalError, Finding, HeaderMutation, JsonPatch, PatchOp};
    use apf_proto::prost_types::{Struct, Value as ProtoValue, value};

    use super::*;

    const MCP_FIXTURE: &[u8] = br#"{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send","arguments":{"to":"fixture-recipient@example.com","subject":"test"}}}"#;

    struct StubEvaluator {
        result: EvalResult,
        fail: bool,
        inputs: Mutex<Vec<EvalInput>>,
    }

    impl StubEvaluator {
        fn returning(result: EvalResult) -> Self {
            Self {
                result,
                fail: false,
                inputs: Mutex::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                result: EvalResult::default(),
                fail: true,
                inputs: Mutex::new(Vec::new()),
            }
        }

        fn inputs(&self) -> Vec<EvalInput> {
            self.inputs
                .lock()
                .expect("test evaluator input lock should not be poisoned")
                .clone()
        }
    }

    impl Evaluator for StubEvaluator {
        fn evaluate(&self, input: EvalInput) -> Result<EvalResult, EvalError> {
            self.inputs
                .lock()
                .expect("test evaluator input lock should not be poisoned")
                .push(input);
            if self.fail {
                Err(EvalError::Engine("fixture evaluator failure".to_string()))
            } else {
                Ok(self.result.clone())
            }
        }
    }

    struct PanickingEvaluator;

    impl Evaluator for PanickingEvaluator {
        fn evaluate(&self, _input: EvalInput) -> Result<EvalResult, EvalError> {
            panic!("fixture evaluator panic")
        }
    }

    fn make_service(evaluator: impl Evaluator + 'static) -> SupervisorMiddlewareService {
        let (_, rx) = tokio::sync::watch::channel(Arc::new(evaluator) as Arc<dyn Evaluator>);
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Insecure,
        }
    }

    fn make_service_arc(evaluator: Arc<dyn Evaluator>) -> SupervisorMiddlewareService {
        let (_, rx) = tokio::sync::watch::channel(evaluator);
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Insecure,
        }
    }

    fn make_authenticated_service_arc(
        evaluator: Arc<dyn Evaluator>,
    ) -> SupervisorMiddlewareService {
        let (_, rx) = tokio::sync::watch::channel(evaluator);
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Required {
                expected_audience: "urn:openshell:extension:middleware:test".to_string(),
            },
        }
    }

    fn authenticated_request<T>(
        message: T,
        kind: ExtensionCallerKind,
        sandbox_id: Option<&str>,
    ) -> Request<T> {
        let mut request = Request::new(message);
        request
            .extensions_mut()
            .insert(AuthenticatedCaller::for_test(kind, sandbox_id));
        request
    }

    fn evaluation(body: &[u8]) -> wire::HttpRequestEvaluation {
        wire::HttpRequestEvaluation {
            phase: wire::SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(wire::RequestContext {
                request_id: "request-017".to_string(),
                sandbox_id: "sandbox-042".to_string(),
                originating_process: None,
            }),
            config: Some(Struct::default()),
            target: Some(wire::HttpRequestTarget {
                scheme: "https".to_string(),
                host: "api.example.com".to_string(),
                port: 443,
                method: "POST".to_string(),
                path: "/mcp".to_string(),
                query: String::new(),
            }),
            headers: Vec::new(),
            body: body.to_vec(),
            middleware_name: SERVICE_NAME.to_string(),
        }
    }

    #[tokio::test]
    async fn describe_advertises_exact_v1_binding() {
        let service = make_service(StubEvaluator::returning(EvalResult::default()));
        let manifest = service
            .describe(Request::new(()))
            .await
            .expect("Describe should be infallible")
            .into_inner();

        assert_eq!(manifest.name, SERVICE_NAME);
        assert_eq!(manifest.service_version, env!("CARGO_PKG_VERSION"));
        assert!(manifest.expected_audience.is_empty());
        assert_eq!(
            manifest.bindings,
            vec![wire::MiddlewareBinding {
                operation: wire::SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: wire::SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_BODY_BYTES as u64,
                timeout: String::new(),
            }]
        );
    }

    #[tokio::test]
    async fn authenticated_methods_enforce_the_caller_matrix_and_advertise_audience() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_authenticated_service_arc(evaluator.clone());

        for (kind, sandbox_id) in [
            (ExtensionCallerKind::Gateway, None),
            (ExtensionCallerKind::Supervisor, Some("sandbox-042")),
        ] {
            let manifest = service
                .describe(authenticated_request((), kind, sandbox_id))
                .await
                .expect("Describe accepts gateway and supervisor callers")
                .into_inner();
            assert_eq!(
                manifest.expected_audience,
                "urn:openshell:extension:middleware:test"
            );
        }

        let validate = wire::ValidateConfigRequest {
            config: Some(Struct::default()),
            middleware_name: SERVICE_NAME.to_string(),
        };
        service
            .validate_config(authenticated_request(
                validate.clone(),
                ExtensionCallerKind::Gateway,
                None,
            ))
            .await
            .expect("ValidateConfig accepts a gateway caller");
        assert_eq!(
            service
                .validate_config(authenticated_request(
                    validate,
                    ExtensionCallerKind::Supervisor,
                    Some("sandbox-042"),
                ))
                .await
                .expect_err("ValidateConfig rejects a supervisor caller")
                .code(),
            tonic::Code::PermissionDenied
        );

        service
            .evaluate_http_request(authenticated_request(
                evaluation(b"not-json"),
                ExtensionCallerKind::Supervisor,
                Some("sandbox-042"),
            ))
            .await
            .expect("EvaluateHttpRequest accepts its matching supervisor caller");
        assert_eq!(
            service
                .evaluate_http_request(authenticated_request(
                    evaluation(b"not-json"),
                    ExtensionCallerKind::Gateway,
                    None,
                ))
                .await
                .expect_err("EvaluateHttpRequest rejects a gateway caller")
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(evaluator.inputs().len(), 1);

        assert_eq!(
            service
                .describe(Request::new(()))
                .await
                .expect_err("authenticated dispatch must reject a missing caller")
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn supervisor_sandbox_mismatch_is_rejected_before_policy_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_authenticated_service_arc(evaluator.clone());
        let error = service
            .evaluate_http_request(authenticated_request(
                evaluation(b"not-json"),
                ExtensionCallerKind::Supervisor,
                Some("sandbox-other"),
            ))
            .await
            .expect_err("a supervisor token cannot evaluate another sandbox")
            .code();

        assert_eq!(error, tonic::Code::PermissionDenied);
        assert!(
            evaluator.inputs().is_empty(),
            "identity mismatch must fail before evaluator invocation"
        );
    }

    #[tokio::test]
    async fn validate_config_accepts_only_empty_config_without_reflecting_values() {
        let service = make_service(StubEvaluator::returning(EvalResult::default()));
        for config in [None, Some(Struct::default())] {
            let result = service
                .validate_config(Request::new(wire::ValidateConfigRequest {
                    config,
                    middleware_name: SERVICE_NAME.to_string(),
                }))
                .await
                .expect("empty config validation should be infallible")
                .into_inner();
            assert!(result.valid);
            assert!(result.reason.is_empty());
        }

        let config = Struct {
            fields: std::collections::BTreeMap::from([(
                "fixture".to_string(),
                ProtoValue {
                    kind: Some(value::Kind::StringValue(
                        "fixture-config-secret".to_string(),
                    )),
                },
            )]),
        };
        let result = service
            .validate_config(Request::new(wire::ValidateConfigRequest {
                config: Some(config),
                middleware_name: SERVICE_NAME.to_string(),
            }))
            .await
            .expect("invalid config should return a validation result")
            .into_inner();
        assert!(!result.valid);
        assert_eq!(
            result.reason,
            "configuration must be empty; received 1 field(s)"
        );
        assert!(!result.reason.contains("fixture-config-secret"));
    }

    #[tokio::test]
    async fn mcp_tool_call_passes_public_name_as_tool() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());

        let result = service
            .evaluate_http_request(Request::new(evaluation(MCP_FIXTURE)))
            .await
            .expect("mapped request should return a wire decision")
            .into_inner();

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        let inputs = evaluator.inputs();
        let input = inputs
            .first()
            .expect("one evaluator input should be recorded");
        assert_eq!(input.tool.as_deref(), Some("outlook_message_send"));
        assert!(input.capability.is_none());
        assert!(input.has_tool_name);
        assert_eq!(input.args["to"], "fixture-recipient@example.com");
        assert_eq!(input.user_subject, "");
        assert_eq!(
            input.target,
            Some(RequestTarget {
                host: "api.example.com".to_string(),
                method: "POST".to_string(),
                path: "/mcp".to_string(),
                scheme: "https".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn fixed_fixture_runs_through_evaluate_apply_wire_pipeline() {
        let result = EvalResult {
            body_replacement: Some("{\"redacted\":true}".to_string()),
            header_mutations: vec![HeaderMutation {
                name: "x-openshell-middleware-policy".to_string(),
                action: HeaderAction::Set,
                value: Some("applied".to_string()),
            }],
            findings: vec![Finding {
                kind: "content".to_string(),
                label: "sensitive".to_string(),
                severity: Severity::High,
                confidence: Some(95),
            }],
            verdict: Verdict::Warn,
            reason: Some("content_detected".to_string()),
            message: Some("request content requires review".to_string()),
            ..EvalResult::default()
        };
        let evaluator = Arc::new(StubEvaluator::returning(result));
        let service = make_service_arc(evaluator.clone());

        let result = service
            .evaluate_http_request(Request::new(evaluation(MCP_FIXTURE)))
            .await
            .expect("mapped request should return applied effects")
            .into_inner();

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        assert!(result.has_body);
        assert_eq!(result.body, br#"{"redacted":true}"#);
        assert_eq!(result.header_mutations.len(), 1);
        assert_eq!(
            result.header_mutations[0].operation,
            Some(wire::header_mutation::Operation::Write(wire::WriteHeader {
                name: "x-openshell-middleware-policy".to_string(),
                value: "applied".to_string(),
                on_existing: wire::ExistingHeaderAction::Overwrite as i32,
            }))
        );
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].r#type, "content");
        assert_eq!(result.findings[0].confidence, "95");
        assert_eq!(result.findings[1].r#type, "policy_verdict");
        assert_eq!(result.findings[1].label, "warn");
        assert_eq!(evaluator.inputs().len(), 1);
    }

    #[test]
    fn json_patch_success_and_missing_path_follow_apply_effects() {
        let patch = JsonPatch {
            op: PatchOp::Replace,
            path: "/params/arguments/subject".to_string(),
            value: Some(Value::String("[REDACTED]".to_string())),
        };
        let service = make_service(StubEvaluator::returning(EvalResult {
            body_patches: vec![patch],
            ..EvalResult::default()
        }));

        let patched = service.evaluate(&evaluation(MCP_FIXTURE));

        assert_eq!(patched.decision, wire::Decision::Allow as i32);
        assert!(patched.has_body);
        let patched_json = serde_json::from_slice::<Value>(&patched.body)
            .expect("patched middleware body should remain JSON");
        assert_eq!(patched_json["params"]["arguments"]["subject"], "[REDACTED]");

        let service = make_service(StubEvaluator::returning(EvalResult {
            body_patches: vec![JsonPatch {
                op: PatchOp::Replace,
                path: "/params/missing".to_string(),
                value: Some(Value::Bool(true)),
            }],
            ..EvalResult::default()
        }));
        let missing = service.evaluate(&evaluation(MCP_FIXTURE));
        assert_eq!(missing.decision, wire::Decision::Deny as i32);
        assert_eq!(missing.reason_code, CODE_EFFECT_APPLICATION_FAILED);
    }

    #[test]
    fn header_mutations_preserve_order_and_action_semantics() {
        let evaluator_result = EvalResult {
            header_mutations: vec![
                HeaderMutation {
                    name: "x-openshell-middleware-chain".to_string(),
                    action: HeaderAction::Set,
                    value: Some("first".to_string()),
                },
                HeaderMutation {
                    name: "x-openshell-middleware-chain".to_string(),
                    action: HeaderAction::Add,
                    value: Some("second".to_string()),
                },
                HeaderMutation {
                    name: "x-visible-header".to_string(),
                    action: HeaderAction::Remove,
                    value: None,
                },
            ],
            ..EvalResult::default()
        };
        let service = make_service(StubEvaluator::returning(evaluator_result));

        let result = service.evaluate(&evaluation(b"plain text"));

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        assert_eq!(result.header_mutations.len(), 3);
        assert!(matches!(
            result.header_mutations[0].operation.as_ref(),
            Some(wire::header_mutation::Operation::Write(write))
                if write.on_existing == wire::ExistingHeaderAction::Overwrite as i32
        ));
        assert!(matches!(
            result.header_mutations[1].operation.as_ref(),
            Some(wire::header_mutation::Operation::Write(write))
                if write.on_existing == wire::ExistingHeaderAction::Append as i32
        ));
        assert!(matches!(
            result.header_mutations[2].operation.as_ref(),
            Some(wire::header_mutation::Operation::Remove(_))
        ));
    }

    #[tokio::test]
    async fn non_mcp_and_non_json_bodies_still_reach_evaluator() {
        for body in [
            br#"{"message":"hello"}"#.as_slice(),
            b"\x00\xffbinary",
            b"text/plain documentation mentions tools/call",
        ] {
            let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
            let service = make_service_arc(evaluator.clone());
            let result = service
                .evaluate_http_request(Request::new(evaluation(body)))
                .await
                .expect("protocol-neutral request should be evaluated")
                .into_inner();
            assert_eq!(result.decision, wire::Decision::Allow as i32);
            let input = evaluator
                .inputs()
                .pop()
                .expect("one input should be recorded");
            assert!(input.tool.is_none());
            assert!(input.capability.is_none());
            assert!(!input.has_tool_name);
            assert!(!input.body_text.is_empty());
        }
    }

    #[test]
    fn allow_without_effects_preserves_request_body() {
        let service = make_service(StubEvaluator::returning(EvalResult::default()));

        let result = service.evaluate(&evaluation(b"original request body"));

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        assert!(!result.has_body);
        assert!(result.body.is_empty());
    }

    #[test]
    fn explicit_empty_replacement_replaces_the_request_body() {
        let service = make_service(StubEvaluator::returning(EvalResult {
            body_replacement: Some(String::new()),
            ..EvalResult::default()
        }));

        let result = service.evaluate(&evaluation(b"original request body"));

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        assert!(result.has_body);
        assert!(result.body.is_empty());
    }

    #[test]
    fn mcp_tool_call_without_arguments_maps_empty_arguments() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let body = br#"{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send"}}"#;

        let result = service.evaluate(&evaluation(body));

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        let input = evaluator
            .inputs()
            .pop()
            .expect("one evaluator input should be recorded");
        assert!(input.args.is_empty());
    }

    #[test]
    fn malformed_mcp_fields_are_denied_before_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let bodies: &[&[u8]] = &[
            br#"{"jsonrpc":"2.0","method":"tools/call"}"#,
            br#"{"jsonrpc":"2.0","method":"tools/call","params":[]}"#,
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":17}}"#,
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"outlook_message_send","arguments":[]}}"#,
        ];

        for body in bodies {
            let result = service.evaluate(&evaluation(body));
            assert_eq!(result.decision, wire::Decision::Deny as i32);
            assert_eq!(result.reason_code, CODE_INVALID_MCP_REQUEST);
        }
        assert!(evaluator.inputs().is_empty());
    }

    #[test]
    fn malformed_json_with_tool_call_intent_is_denied_before_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let bodies: &[&[u8]] = &[
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{}} trailing"#,
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{}} trailing"#,
        ];

        for body in bodies {
            let result = service.evaluate(&evaluation(body));
            assert_eq!(result.decision, wire::Decision::Deny as i32);
            assert_eq!(result.reason_code, CODE_INVALID_MCP_REQUEST);
        }
        assert!(evaluator.inputs().is_empty());
    }

    #[test]
    fn mcp_tool_call_batch_is_denied_before_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let body = br#"[{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send","arguments":{}}}]"#;

        let result = service.evaluate(&evaluation(body));

        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_INVALID_MCP_REQUEST);
        assert!(evaluator.inputs().is_empty());
    }

    #[test]
    fn nested_mcp_tool_call_batch_is_denied_before_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let body = br#"[[{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send","arguments":{}}}]]"#;

        let result = service.evaluate(&evaluation(body));

        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_INVALID_MCP_REQUEST);
        assert!(evaluator.inputs().is_empty());
    }

    #[test]
    fn advisory_escalation_stays_allow_with_finding() {
        let evaluator_result = EvalResult {
            verdict: Verdict::Escalate,
            reason: Some("approval_required".to_string()),
            ..EvalResult::default()
        };
        let service = make_service(StubEvaluator::returning(evaluator_result));

        let result = service.evaluate(&evaluation(b"plain text"));

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].r#type, "policy_verdict");
        assert_eq!(result.findings[0].label, "escalate");
        assert_eq!(result.findings[0].severity, "high");
    }

    #[tokio::test]
    async fn evaluator_error_fails_closed() {
        let service = make_service(StubEvaluator::failing());
        let result = service
            .evaluate_http_request(Request::new(evaluation(b"plain text")))
            .await
            .expect("evaluator error should become a deny")
            .into_inner();
        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_EVALUATION_FAILED);
        assert!(!result.reason.contains("fixture evaluator failure"));
    }

    #[tokio::test]
    async fn evaluator_panic_in_blocking_task_fails_closed() {
        let service = make_service(PanickingEvaluator);

        let result = service
            .evaluate_http_request(Request::new(evaluation(b"plain text")))
            .await
            .expect("blocking-task failure should become a deny")
            .into_inner();

        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_EVALUATION_FAILED);
    }

    #[tokio::test]
    async fn apply_error_fails_closed() {
        let result = EvalResult {
            body_patches: vec![JsonPatch {
                op: PatchOp::Replace,
                path: "/secret".to_string(),
                value: Some(Value::String("redacted".to_string())),
            }],
            ..EvalResult::default()
        };
        let service = make_service(StubEvaluator::returning(result));
        let result = service
            .evaluate_http_request(Request::new(evaluation(b"plain text")))
            .await
            .expect("application error should become a deny")
            .into_inner();
        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_EFFECT_APPLICATION_FAILED);
    }

    #[test]
    fn invalid_request_envelope_fields_fail_closed_before_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());

        let mut invalid_phase = evaluation(b"plain text");
        invalid_phase.phase = wire::SupervisorMiddlewarePhase::Unspecified as i32;
        let mut invalid_config = evaluation(b"plain text");
        invalid_config.config = Some(Struct {
            fields: std::collections::BTreeMap::from([(
                "unexpected".to_string(),
                ProtoValue::default(),
            )]),
        });
        let mut missing_target = evaluation(b"plain text");
        missing_target.target = None;
        let oversized_body = evaluation(&vec![b'x'; MAX_BODY_BYTES + 1]);

        for (request, reason_code) in [
            (invalid_phase, CODE_INVALID_PHASE),
            (invalid_config, CODE_INVALID_CONFIG),
            (missing_target, CODE_MISSING_TARGET),
            (oversized_body, CODE_BODY_TOO_LARGE),
        ] {
            let result = service.evaluate(&request);
            assert_eq!(result.decision, wire::Decision::Deny as i32);
            assert_eq!(result.reason_code, reason_code);
        }
        assert!(evaluator.inputs().is_empty());
    }

    #[test]
    fn oversized_policy_outputs_fail_closed() {
        let results = [
            (
                EvalResult {
                    body_replacement: Some("x".repeat(MAX_BODY_BYTES + 1)),
                    ..EvalResult::default()
                },
                CODE_REPLACEMENT_BODY_TOO_LARGE,
            ),
            (
                EvalResult {
                    header_mutations: vec![HeaderMutation {
                        name: "x-openshell-middleware-policy".to_string(),
                        action: HeaderAction::Set,
                        value: Some("x".repeat(MAX_HEADER_MUTATION_DATA_BYTES)),
                    }],
                    ..EvalResult::default()
                },
                CODE_INVALID_HEADER_MUTATION,
            ),
            (
                EvalResult {
                    header_mutations: vec![
                        HeaderMutation {
                            name: "x-openshell-middleware-policy".to_string(),
                            action: HeaderAction::Set,
                            value: Some("applied".to_string()),
                        };
                        MAX_HEADER_MUTATIONS + 1
                    ],
                    ..EvalResult::default()
                },
                CODE_INVALID_HEADER_MUTATION,
            ),
            (
                EvalResult {
                    findings: vec![Finding {
                        kind: "content".to_string(),
                        label: "x".repeat(MAX_FINDING_BYTES),
                        severity: Severity::High,
                        confidence: None,
                    }],
                    ..EvalResult::default()
                },
                CODE_INVALID_FINDINGS,
            ),
            (
                EvalResult {
                    findings: vec![
                        Finding {
                            kind: "content".to_string(),
                            label: "credential".to_string(),
                            severity: Severity::High,
                            confidence: None,
                        };
                        MAX_FINDINGS_PER_STAGE + 1
                    ],
                    ..EvalResult::default()
                },
                CODE_INVALID_FINDINGS,
            ),
        ];

        for (evaluator_result, reason_code) in results {
            let service = make_service(StubEvaluator::returning(evaluator_result));
            let result = service.evaluate(&evaluation(b"plain text"));
            assert_eq!(result.decision, wire::Decision::Deny as i32);
            assert_eq!(result.reason_code, reason_code);
        }
    }

    #[tokio::test]
    async fn evaluator_deny_uses_stable_reason_code() {
        let evaluator_reason = "no grant covers outlook.message_delete";
        let result = EvalResult {
            allow: false,
            deny_reason: evaluator_reason.to_string(),
            ..EvalResult::default()
        };
        let service = make_service(StubEvaluator::returning(result));
        let result = service
            .evaluate_http_request(Request::new(evaluation(b"plain text")))
            .await
            .expect("policy denial should be a successful RPC")
            .into_inner();
        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_POLICY_DENIED);
        assert_eq!(result.reason, evaluator_reason);
    }

    #[test]
    fn evaluator_deny_preserves_findings_without_advisory_verdict() {
        let service = make_service(StubEvaluator::returning(EvalResult {
            allow: false,
            deny_reason: "denied with finding".to_string(),
            verdict: Verdict::Escalate,
            findings: vec![Finding {
                kind: "content".to_string(),
                label: "credential".to_string(),
                severity: Severity::High,
                confidence: Some(90),
            }],
            ..EvalResult::default()
        }));

        let result = service.evaluate(&evaluation(b"plain text"));

        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].r#type, "content");
    }

    #[test]
    fn policy_deny_reason_is_bounded_on_a_utf8_boundary() {
        let evaluator_result = EvalResult {
            allow: false,
            deny_reason: "é".repeat(MAX_REASON_BYTES),
            ..EvalResult::default()
        };
        let service = make_service(StubEvaluator::returning(evaluator_result));

        let result = service.evaluate(&evaluation(b"plain text"));

        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason.len(), MAX_REASON_BYTES);
        assert!(result.reason.chars().all(|character| character == 'é'));
    }

    #[tokio::test]
    async fn invalid_header_write_fails_closed() {
        for mutation in [
            HeaderMutation {
                name: "authorization".to_string(),
                action: HeaderAction::Set,
                value: Some("fixture-secret".to_string()),
            },
            HeaderMutation {
                name: "x-openshell-middleware-safe\r\nx-evil".to_string(),
                action: HeaderAction::Set,
                value: Some("fixture-secret".to_string()),
            },
            HeaderMutation {
                name: "authorization".to_string(),
                action: HeaderAction::Remove,
                value: None,
            },
            HeaderMutation {
                name: "x-openshell-middleware-safe".to_string(),
                action: HeaderAction::Set,
                value: Some("safe\r\ninjected".to_string()),
            },
            HeaderMutation {
                name: "x-openshell-middleware-safe".to_string(),
                action: HeaderAction::Set,
                value: None,
            },
            HeaderMutation {
                name: "x-openshell-middleware-safe".to_string(),
                action: HeaderAction::Add,
                value: None,
            },
            HeaderMutation {
                name: "x-amz-security-token".to_string(),
                action: HeaderAction::Remove,
                value: None,
            },
            HeaderMutation {
                name: "x-openshell-credential-token".to_string(),
                action: HeaderAction::Remove,
                value: None,
            },
        ] {
            let evaluator_result = EvalResult {
                header_mutations: vec![mutation],
                ..EvalResult::default()
            };
            let service = make_service(StubEvaluator::returning(evaluator_result));
            let result = service
                .evaluate_http_request(Request::new(evaluation(b"plain text")))
                .await
                .expect("invalid header mutation should become a deny")
                .into_inner();
            assert_eq!(result.decision, wire::Decision::Deny as i32);
            assert_eq!(result.reason_code, CODE_INVALID_HEADER_MUTATION);
            assert!(!result.reason.contains("fixture-secret"));
        }
    }
}
