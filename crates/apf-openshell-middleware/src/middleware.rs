// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell supervisor-middleware request adapter.
//!
//! The adapter owns only OpenShell wire translation. Policy evaluation and
//! effect application stay in `apf-policy-eval`, so every enforcement point
//! shares the same decision and mutation semantics.

use std::fmt;
use std::sync::Arc;

use crate::audit::{BindingMismatch, EgressRecord, MiddlewareAudit};
use apf_audit::SanitizationGuard;

use tracing::{debug, info, warn};

use apf_policy_eval::{
    ActivePolicy, EvalInput, EvalResult, Finding as EvalFinding, HeaderAction,
    HeaderMutation as EvalHeaderMutation, RequestTarget, Severity, Verdict, apply_effects,
};
use prost::Message;
use serde::Deserialize;
use serde_json::{Map, Value};
use tonic::{Request, Response, Status};

use apf_openshell_auth::protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
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
/// The request-derived strings a record needs. Named rather than positional:
/// all four are strings, and a swap produces a plausible, wrong record.
#[derive(Clone, Copy)]
struct RequestFacts<'a> {
    host: &'a str,
    method: &'a str,
    sandbox_id: &'a str,
    /// The wire's `request_id`, joining this record to the supervisor's log.
    correlation_id: &'a str,
    /// The MCP tool the request invoked, where one was parsed.
    tool: Option<&'a str>,
}

#[derive(Clone)]
pub struct SupervisorMiddlewareService {
    evaluator: tokio::sync::watch::Receiver<Arc<ActivePolicy>>,
    authentication: AuthenticationMode,
    audit: MiddlewareAudit,
}

/// Schema cap on `advisory_signals.findings`.
const MAX_AUDIT_FINDINGS: usize = 32;

/// Size-limited supervisor middleware server protected by extension JWT authentication.
pub type AuthenticatedSupervisorMiddlewareServer =
    Authenticated<SupervisorMiddlewareServer<SupervisorMiddlewareService>>;

impl SupervisorMiddlewareService {
    /// Builds a size-limited server that authenticates every OpenShell call before dispatch.
    #[must_use]
    pub fn authenticated_server(
        evaluator: tokio::sync::watch::Receiver<Arc<ActivePolicy>>,
        verifier: ExtensionAuthVerifier,
        audit: MiddlewareAudit,
    ) -> AuthenticatedSupervisorMiddlewareServer {
        // See the interceptor's constructor: wiring the verifier's sink here
        // makes an authenticated listener that records nothing unrepresentable.
        let verifier = verifier.with_audit(audit.component());
        let service = Self {
            evaluator,
            authentication: AuthenticationMode::Required {
                expected_audience: verifier.audience().to_string(),
            },
            audit,
        };
        Authenticated::new(service.into_size_limited_server(), verifier)
    }

    /// Builds a size-limited server with authentication deliberately disabled.
    ///
    /// This mode is only for a matching OpenShell registration whose
    /// `allow_insecure_transport` setting explicitly opts out of extension authentication.
    #[must_use]
    pub fn insecure_server(
        evaluator: tokio::sync::watch::Receiver<Arc<ActivePolicy>>,
        audit: MiddlewareAudit,
    ) -> SupervisorMiddlewareServer<Self> {
        Self {
            evaluator,
            authentication: AuthenticationMode::Insecure,
            audit,
        }
        .into_size_limited_server()
    }

    /// Record a caller this listener refused after the credential stage.
    fn record_authorization_failure<T>(&self, request: &Request<T>, failure: AuthorizationFailure) {
        // Only the not-allowed branch has a caller to name; the other means
        // none was ever established.
        let caller_kind = request
            .extensions()
            .get::<AuthenticatedCaller>()
            .map(AuthenticatedCaller::kind);
        if let Err(e) = apf_openshell_auth::audit::emit_authorization_failure(
            &self.audit.component(),
            failure,
            caller_kind,
        ) {
            warn!(error = %e, "audit emission failed for extension authorization");
        }
    }

    /// Record a supervisor credential used on a request claiming another
    /// sandbox — one sandbox acting as another.
    ///
    /// Identity, not policy: no bundle was consulted, so the record names none.
    fn record_binding_mismatch(&self, ids: &BindingMismatch<'_>) {
        if let Err(e) = self.audit.emit_sandbox_binding_mismatch(ids) {
            warn!(error = %e, "audit emission failed for sandbox binding mismatch");
        }
    }

    /// Record one egress decision, read off the result rather than built at
    /// each branch that produced it.
    ///
    /// Covers every path out of `evaluate`, including the panic fallback, so a
    /// refusal added there cannot skip the record. Refusals raised earlier do
    /// not reach here: binding mismatch and authentication failure each have
    /// their own event.
    fn record_egress(
        &self,
        response: &wire::HttpRequestResult,
        verdict: Option<Verdict>,
        effects: apf_audit::Effects,
        request: &RequestFacts<'_>,
        active: &ActivePolicy,
    ) {
        let RequestFacts {
            host,
            method,
            sandbox_id,
            correlation_id,
            tool,
        } = *request;
        let allowed = response.decision == wire::Decision::Allow as i32;

        // `POST` does not satisfy the verb profile, so the raw method coerced
        // to the sentinel on every record. Namespaced and lowercased, matching
        // the shape the PDP and interceptor already use.
        let verb = if method.is_empty() {
            "http.request".to_owned()
        } else {
            format!("http.{}", method.to_ascii_lowercase())
        };

        // The verdict comes from the evaluator, not from the wire. The wire
        // carries it as a trailing `policy_verdict` finding, and nothing
        // distinguishes that stand-in from a real finding a policy defines with
        // the same kind — so reading it back could both fabricate a verdict and
        // drop the real observation.
        let verdict = verdict.map(|v| match v {
            Verdict::Escalate => apf_audit::Verdict::Escalate,
            Verdict::Warn => apf_audit::Verdict::Warn,
            Verdict::Allow => apf_audit::Verdict::Allow,
        });

        // `map_findings` appends the stand-in only on the allow path and only
        // for a non-default verdict, so its presence is derived from those two
        // facts rather than matched by kind — nothing on the wire distinguishes
        // it from a real finding a policy defines with the same kind.
        let stand_in = allowed && matches!(verdict, Some(v) if v != apf_audit::Verdict::Allow);
        let real_count = response
            .findings
            .len()
            .saturating_sub(usize::from(stand_in));
        let real_findings: Vec<&wire::Finding> =
            response.findings.iter().take(real_count).collect();

        // The wire codes are unprefixed and would sit unnamespaced beside the
        // PDP's `policy.request_denied` in a shared log.
        let reason_code = if !response.reason_code.is_empty() {
            format!("middleware.{}", response.reason_code)
        } else if real_findings.is_empty() {
            "middleware.allowed".to_owned()
        } else {
            "middleware.allowed_with_findings".to_owned()
        };

        let findings: Vec<apf_audit::Finding> = real_findings
            .into_iter()
            .take(MAX_AUDIT_FINDINGS)
            .map(|f| apf_audit::Finding {
                kind: f.r#type.chars().take(256).collect(),
                label: f.label.chars().take(256).collect(),
                severity: match f.severity.as_str() {
                    "critical" => apf_audit::Severity::Critical,
                    "high" => apf_audit::Severity::High,
                    "medium" => apf_audit::Severity::Medium,
                    _ => apf_audit::Severity::Low,
                },
                confidence: f.confidence.parse::<u8>().ok().map(|c| c.min(100)),
            })
            .collect();

        if let Err(e) = self.audit.emit_egress(&EgressRecord {
            allowed,
            resource_kind: "openshell.egress",
            host,
            verb: &verb,
            tool,
            reason_code: &reason_code,
            reason: &response.reason,
            sandbox_id,
            correlation_id,
            verdict,
            findings: &findings,
            effects,
            policy_digest: &active.bundle_digest,
            policy_revision: Some(active.policy_revision).filter(|v| *v != 0),
        }) {
            warn!(error = %e, "audit emission failed for egress decision");
        }
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
        request: Request<wire::MiddlewareDescribeRequest>,
    ) -> Result<Response<wire::MiddlewareManifest>, Status> {
        self.authentication
            .authorize(
                &request,
                &[
                    ExtensionCallerKind::Gateway,
                    ExtensionCallerKind::Supervisor,
                ],
            )
            .map_err(|failure| {
                self.record_authorization_failure(&request, failure);
                failure.into_status()
            })?;
        let manifest = wire::MiddlewareManifest {
            name: SERVICE_NAME.to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings: vec![wire::MiddlewareBinding {
                operation: wire::SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: wire::SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_BODY_BYTES as u64,
                // An absent binding timeout inherits the operator-owned
                // deadline instead of silently shortening it.
                request_timeout: None,
            }],
            expected_audience: self.authentication.expected_audience().to_string(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "apf/content-policy",
                env!("CARGO_PKG_VERSION"),
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            &manifest.name,
            manifest
                .extension
                .as_ref()
                .expect("middleware manifest protocol metadata is static"),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<wire::ValidateConfigRequest>,
    ) -> Result<Response<wire::ValidateConfigResponse>, Status> {
        self.authentication
            .authorize(&request, &[ExtensionCallerKind::Gateway])
            .map_err(|failure| {
                self.record_authorization_failure(&request, failure);
                failure.into_status()
            })?;
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
            .map_err(|failure| {
                self.record_authorization_failure(&request, failure);
                failure.into_status()
            })?
            .and_then(AuthenticatedCaller::sandbox_id)
            .map(str::to_owned);
        let evaluation = request.into_inner();
        // Both sides are needed for the record: which sandbox the credential is
        // bound to, and which one the request claimed.
        let bound_sandbox = authenticated_sandbox.clone().unwrap_or_default();
        let claimed_sandbox = evaluation
            .context
            .as_ref()
            .map_or_else(String::new, |c| c.sandbox_id.clone());
        if authenticated_sandbox.is_some_and(|sandbox_id| {
            evaluation
                .context
                .as_ref()
                .is_none_or(|context| context.sandbox_id != sandbox_id)
        }) {
            // A valid supervisor token is scoped to exactly one sandbox. Bind
            // that identity before parsing request content or invoking policy.
            self.record_binding_mismatch(&BindingMismatch {
                bound_sandbox: &bound_sandbox,
                claimed_sandbox: &claimed_sandbox,
            });
            return Err(Status::permission_denied(
                "OpenShell supervisor sandbox does not match the request context",
            ));
        }
        // Read once and passed into the evaluation: reading again inside would
        // let a hot-swap between the two put one policy in the record and
        // another in the decision.
        let active = Arc::clone(&*self.evaluator.borrow());
        let (host, method) = evaluation
            .target
            .as_ref()
            .map_or((String::new(), String::new()), |t| {
                (t.host.clone(), t.method.clone())
            });
        let (sandbox_id, correlation_id) = evaluation
            .context
            .as_ref()
            .map_or((String::new(), String::new()), |c| {
                (c.sandbox_id.clone(), c.request_id.clone())
            });

        let service = self.clone();
        let deciding = Arc::clone(&active);
        let (response, verdict, effects, tool) =
            tokio::task::spawn_blocking(move || service.evaluate(&evaluation, &deciding))
                .await
                .unwrap_or_else(|_| {
                    // A panic or runtime shutdown in the blocking task must not
                    // escape as a gRPC failure that OpenShell could fail open.
                    (
                        deny(CODE_EVALUATION_FAILED, "policy evaluation failed"),
                        None,
                        apf_audit::Effects::default(),
                        None,
                    )
                });

        // One emit at the single exit, reading the result rather than each
        // branch that built it: a refusal added later cannot skip the record.
        self.record_egress(
            &response,
            verdict,
            effects,
            &RequestFacts {
                host: &host,
                method: &method,
                sandbox_id: &sandbox_id,
                correlation_id: &correlation_id,
                tool: tool.as_deref(),
            },
            &active,
        );

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
    /// Returns the wire result and the verdict the evaluator produced.
    ///
    /// The verdict is returned rather than read back off the wire: the wire
    /// carries it as a `policy_verdict` finding, and nothing distinguishes that
    /// stand-in from a real finding a policy defines with the same kind.
    fn evaluate(
        &self,
        evaluation: &wire::HttpRequestEvaluation,
        active: &ActivePolicy,
    ) -> (
        wire::HttpRequestResult,
        Option<Verdict>,
        apf_audit::Effects,
        Option<String>,
    ) {
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
            return (
                deny(CODE_INVALID_PHASE, "unsupported middleware phase"),
                None,
                apf_audit::Effects::default(),
                None,
            );
        }
        if evaluation
            .config
            .as_ref()
            .is_some_and(|config| !config.fields.is_empty())
        {
            return (
                deny(
                    CODE_INVALID_CONFIG,
                    "middleware configuration must be empty",
                ),
                None,
                apf_audit::Effects::default(),
                None,
            );
        }
        if evaluation.body.len() > MAX_BODY_BYTES {
            return (
                deny(CODE_BODY_TOO_LARGE, "request body exceeds middleware limit"),
                None,
                apf_audit::Effects::default(),
                None,
            );
        }

        let body_json = match serde_json::from_slice::<Value>(&evaluation.body) {
            Ok(value) => Some(value),
            Err(_) if contains_mcp_tool_call_intent(&evaluation.body) => {
                // A malformed body that still identifies tools/call cannot
                // shed its tool identity and fall through to generic policy.
                return (
                    deny(CODE_INVALID_MCP_REQUEST, "invalid MCP tools/call request"),
                    None,
                    apf_audit::Effects::default(),
                    None,
                );
            }
            Err(_) => None,
        };
        let input = match build_eval_input(evaluation, body_json.as_ref()) {
            Ok(input) => input,
            Err(error) => {
                return (
                    deny(error.reason_code(), error.reason()),
                    None,
                    apf_audit::Effects::default(),
                    None,
                );
            }
        };

        // Kept for the audit record: the evaluator consumes the input, and the
        // record must name the tool the decision was actually about.
        let tool = input.tool.clone();

        // One read: the evaluator and the digest of the policy it came from
        // travel together, so a hot-swap cannot pair a decision with another
        // policy's identity.
        let Ok(result) = active.evaluator.evaluate(input) else {
            // Evaluator errors are intentionally not reflected: backend error
            // text is not a stable or audit-safe wire contract.
            return (
                deny(CODE_EVALUATION_FAILED, "policy evaluation failed"),
                None,
                apf_audit::Effects::default(),
                tool,
            );
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
            return (
                policy_deny(&result),
                Some(result.verdict),
                apf_audit::Effects::default(),
                tool,
            );
        }

        let Ok(applied) = apply_effects(&evaluation.body, body_json.as_ref(), &result) else {
            // Forwarding an unmodified request would drop a mandated effect,
            // so every application error is a hard deny.
            return (
                deny(
                    CODE_EFFECT_APPLICATION_FAILED,
                    "policy effects could not be applied",
                ),
                None,
                apf_audit::Effects::default(),
                tool,
            );
        };
        if applied
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_BODY_BYTES)
        {
            return (
                deny(
                    CODE_REPLACEMENT_BODY_TOO_LARGE,
                    "policy replacement body exceeds middleware limit",
                ),
                None,
                apf_audit::Effects::default(),
                tool,
            );
        }

        let Ok(header_mutations) = map_header_mutations(&applied.headers) else {
            return (
                deny(
                    CODE_INVALID_HEADER_MUTATION,
                    "policy produced an invalid header mutation",
                ),
                None,
                apf_audit::Effects::default(),
                tool,
            );
        };
        let Ok(findings) = map_findings(&result, true) else {
            return (
                deny(CODE_INVALID_FINDINGS, "policy produced invalid findings"),
                None,
                apf_audit::Effects::default(),
                tool,
            );
        };

        let (body, has_body) = applied
            .body
            .map_or_else(|| (Vec::new(), false), |replacement| (replacement, true));

        // Built here, not from the wire: the result carries only the final
        // bytes, so a targeted patch and a wholesale replacement are
        // indistinguishable by the time the record is written.
        let effects = applied_effects(&result, &header_mutations);

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

        (
            wire::HttpRequestResult {
                decision: wire::Decision::Allow as i32,
                body,
                has_body,
                header_mutations,
                findings,
                ..Default::default()
            },
            Some(result.verdict),
            effects,
            tool,
        )
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
        context_attributes: Default::default(),
        runtime: None,
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

/// Summarise what was applied, while the evaluator's intent is still visible.
/// The wire carries only the final bytes, so a targeted patch and a wholesale
/// replacement look identical downstream — and the schema has separate fields
/// for them precisely because they are different claims.
fn applied_effects(result: &EvalResult, mutations: &[wire::HeaderMutation]) -> apf_audit::Effects {
    let mut effects = apf_audit::Effects {
        // Names only. A header value is where a policy would put a token.
        header_mutations: mutations
            .iter()
            .filter_map(|m| match m.operation.as_ref()? {
                wire::header_mutation::Operation::Write(w) => {
                    Some(apf_audit::HeaderMutationRecord::new(
                        audit_header_name(&w.name)?,
                        match wire::ExistingHeaderAction::try_from(w.on_existing) {
                            Ok(wire::ExistingHeaderAction::Append) => apf_audit::HeaderAction::Add,
                            // Overwrite is the only other value `map_header_mutation`
                            // produces; anything else is a wire the record cannot
                            // describe, so it is dropped rather than guessed at.
                            Ok(wire::ExistingHeaderAction::Overwrite) => {
                                apf_audit::HeaderAction::Set
                            }
                            _ => return None,
                        },
                    ))
                }
                wire::header_mutation::Operation::Remove(r) => {
                    Some(apf_audit::HeaderMutationRecord::new(
                        audit_header_name(&r.name)?,
                        apf_audit::HeaderAction::Remove,
                    ))
                }
            })
            .collect(),
        ..apf_audit::Effects::default()
    };

    // A replacement supersedes patches in `apply_effects`, so the record says
    // the same: one claim per request, never both.
    if result.body_replacement.is_some() {
        effects.payload_replaced = Some(true);
    } else if !result.body_patches.is_empty() {
        effects.patch_count = Some(result.body_patches.len() as u64);
        effects.patches = result
            .body_patches
            .iter()
            .filter_map(|p| {
                Some(apf_audit::PatchRecord::new(
                    // Paths only, never operands: the operand is the content
                    // the redaction exists to remove.
                    audit_patch_path(&p.path)?,
                    match p.op {
                        apf_policy_eval::PatchOp::Replace => apf_audit::PatchOp::Replace,
                        apf_policy_eval::PatchOp::Add => apf_audit::PatchOp::Add,
                        apf_policy_eval::PatchOp::Remove => apf_audit::PatchOp::Remove,
                    },
                ))
            })
            .collect();
        effects.truncate_patches();
    }
    effects
}

/// `patch_record.path` and `header_mutation_record.name` maxLength.
const MAX_RECORDED_NAME_CHARS: usize = 256;

/// A patch path as the record can carry it. Same two gates as a header name:
/// a JSON pointer is policy-authored and can be long or credential-shaped.
fn audit_patch_path(path: &str) -> Option<String> {
    let capped: String = path.chars().take(MAX_RECORDED_NAME_CHARS).collect();
    SanitizationGuard::accepts_string(&capped).then_some(capped)
}

/// A header name as the record can carry it, or `None` when it cannot.
///
/// If every name is rejected the effect is omitted entirely — there is no
/// header counterpart to `patch_count` to preserve the fact that headers were
/// rewritten.
///
/// Two gates, and failing either costs the whole record. The wire validator
/// bounds all names and values together rather than each name, so a long one
/// overruns `header_mutation_record.name`. And the guard scans for credential
/// substrings, which an ordinary name can contain — `task-classification` has
/// `sk-` in it. The recorded name may be a 256-char prefix.
fn audit_header_name(name: &str) -> Option<String> {
    let capped: String = name.chars().take(MAX_RECORDED_NAME_CHARS).collect();
    SanitizationGuard::accepts_string(&capped).then_some(capped)
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

/// The wire has no verdict field, so the verdict travels as a finding of this
/// kind. Audit has a real field, so the stand-in is lifted rather than recorded
/// twice.
const VERDICT_FINDING_TYPE: &str = "policy_verdict";

fn verdict_finding(verdict: Verdict) -> Option<wire::Finding> {
    let (label, severity) = match verdict {
        Verdict::Allow => return None,
        Verdict::Warn => ("warn", "medium"),
        Verdict::Escalate => ("escalate", "high"),
    };
    Some(wire::Finding {
        r#type: VERDICT_FINDING_TYPE.to_string(),
        label: label.to_string(),
        count: 1,
        confidence: String::new(),
        severity: severity.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use apf_policy_eval::{EvalError, Evaluator, Finding, HeaderMutation, JsonPatch, PatchOp};
    use apf_proto::prost_types::{Struct, Value as ProtoValue, value};

    use super::*;

    pub(super) const MCP_FIXTURE: &[u8] = br#"{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send","arguments":{"to":"fixture-recipient@example.com","subject":"test"}}}"#;

    pub(super) struct StubEvaluator {
        result: EvalResult,
        fail: bool,
        inputs: Mutex<Vec<EvalInput>>,
    }

    impl StubEvaluator {
        pub(super) fn returning(result: EvalResult) -> Self {
            Self {
                result,
                fail: false,
                inputs: Mutex::new(Vec::new()),
            }
        }

        pub(super) fn failing() -> Self {
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

    /// The policy a test service holds, for the direct `evaluate` calls that
    /// bypass the handler.
    pub(super) fn service_policy(service: &SupervisorMiddlewareService) -> Arc<ActivePolicy> {
        Arc::clone(&service.evaluator.borrow())
    }

    fn make_service(evaluator: impl Evaluator + 'static) -> SupervisorMiddlewareService {
        make_service_arc(Arc::new(evaluator) as Arc<dyn Evaluator>)
    }

    fn make_service_arc(evaluator: Arc<dyn Evaluator>) -> SupervisorMiddlewareService {
        let (_, rx) = tokio::sync::watch::channel(Arc::new(ActivePolicy {
            evaluator,
            bundle_digest: "a".repeat(64),
            policy_revision: 1,
        }));
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Insecure,
            audit: MiddlewareAudit::disabled(),
        }
    }

    pub(super) fn make_audited_service(
        evaluator: impl Evaluator + 'static,
        dir: &std::path::Path,
    ) -> SupervisorMiddlewareService {
        let (tx, rx) = tokio::sync::watch::channel(Arc::new(ActivePolicy {
            evaluator: Arc::new(evaluator) as Arc<dyn Evaluator>,
            bundle_digest: "a".repeat(64),
            policy_revision: 7,
        }));
        // `borrow()` still yields after the sender drops; only `changed()` errors.
        drop(tx);
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Insecure,
            audit: MiddlewareAudit::to_jsonl_in(dir).expect("build emitter"),
        }
    }

    pub(super) fn audit_records(dir: &std::path::Path) -> Vec<apf_audit::AuditEvent> {
        let written =
            std::fs::read_to_string(dir.join("apf-policy-gateway-middleware-audit.jsonl"))
                .expect("audit log was written");
        written
            .lines()
            .map(|line| {
                let parsed: apf_audit::AuditEvent =
                    serde_json::from_str(line).expect("deserializes");
                parsed.validate().expect("validates against the schema");
                parsed
            })
            .collect()
    }

    fn make_authenticated_service_arc(
        evaluator: Arc<dyn Evaluator>,
    ) -> SupervisorMiddlewareService {
        let (_, rx) = tokio::sync::watch::channel(Arc::new(ActivePolicy {
            evaluator,
            bundle_digest: "a".repeat(64),
            policy_revision: 1,
        }));
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Required {
                expected_audience: "urn:openshell:extension:middleware:test".to_string(),
            },
            audit: MiddlewareAudit::disabled(),
        }
    }

    pub(super) fn make_authenticated_audited_service(
        evaluator: impl Evaluator + 'static,
        dir: &std::path::Path,
    ) -> SupervisorMiddlewareService {
        let (_, rx) = tokio::sync::watch::channel(Arc::new(ActivePolicy {
            evaluator: Arc::new(evaluator) as Arc<dyn Evaluator>,
            bundle_digest: "a".repeat(64),
            policy_revision: 1,
        }));
        SupervisorMiddlewareService {
            evaluator: rx,
            authentication: AuthenticationMode::Required {
                expected_audience: "urn:openshell:extension:middleware:test".to_string(),
            },
            audit: MiddlewareAudit::to_jsonl_in(dir).expect("build emitter"),
        }
    }

    pub(super) fn authenticated_request<T>(
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

    fn describe_request() -> wire::MiddlewareDescribeRequest {
        wire::MiddlewareDescribeRequest {
            gateway: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "openshell/gateway",
                "0.0.117",
            )),
        }
    }

    pub(super) fn evaluation(body: &[u8]) -> wire::HttpRequestEvaluation {
        wire::HttpRequestEvaluation {
            phase: wire::SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(wire::RequestContext {
                request_id: "request-017".to_string(),
                sandbox_id: "sandbox-042".to_string(),
                originating_process: None,
                ..Default::default()
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
            .describe(Request::new(describe_request()))
            .await
            .expect("Describe should be infallible")
            .into_inner();

        assert_eq!(manifest.name, SERVICE_NAME);
        assert_eq!(manifest.service_version, env!("CARGO_PKG_VERSION"));
        assert!(manifest.expected_audience.is_empty());
        let metadata = manifest.extension.expect("protocol metadata");
        assert_eq!(
            metadata.supported_capabilities,
            vec!["openshell.supervisor-middleware.contract"]
        );
        assert_eq!(
            manifest.bindings,
            vec![wire::MiddlewareBinding {
                operation: wire::SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: wire::SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_BODY_BYTES as u64,
                request_timeout: None,
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
                .describe(authenticated_request(describe_request(), kind, sandbox_id))
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
                .describe(Request::new(describe_request()))
                .await
                .expect_err("authenticated dispatch must reject a missing caller")
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn describe_rejects_missing_gateway_protocol_metadata() {
        let service = make_service(StubEvaluator::returning(EvalResult::default()));
        let error = service
            .describe(Request::new(wire::MiddlewareDescribeRequest {
                gateway: None,
            }))
            .await
            .expect_err("missing gateway metadata must fail closed");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            error
                .message()
                .contains("did not provide protocol metadata")
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

        let patched = service
            .evaluate(&evaluation(MCP_FIXTURE), &service_policy(&service))
            .0;

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
        let missing = service
            .evaluate(&evaluation(MCP_FIXTURE), &service_policy(&service))
            .0;
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

        let result = service
            .evaluate(&evaluation(b"plain text"), &service_policy(&service))
            .0;

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

        let result = service
            .evaluate(
                &evaluation(b"original request body"),
                &service_policy(&service),
            )
            .0;

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

        let result = service
            .evaluate(
                &evaluation(b"original request body"),
                &service_policy(&service),
            )
            .0;

        assert_eq!(result.decision, wire::Decision::Allow as i32);
        assert!(result.has_body);
        assert!(result.body.is_empty());
    }

    #[test]
    fn mcp_tool_call_without_arguments_maps_empty_arguments() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let body = br#"{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send"}}"#;

        let result = service
            .evaluate(&evaluation(body), &service_policy(&service))
            .0;

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
            let result = service
                .evaluate(&evaluation(body), &service_policy(&service))
                .0;
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
            let result = service
                .evaluate(&evaluation(body), &service_policy(&service))
                .0;
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

        let result = service
            .evaluate(&evaluation(body), &service_policy(&service))
            .0;

        assert_eq!(result.decision, wire::Decision::Deny as i32);
        assert_eq!(result.reason_code, CODE_INVALID_MCP_REQUEST);
        assert!(evaluator.inputs().is_empty());
    }

    #[test]
    fn nested_mcp_tool_call_batch_is_denied_before_evaluation() {
        let evaluator = Arc::new(StubEvaluator::returning(EvalResult::default()));
        let service = make_service_arc(evaluator.clone());
        let body = br#"[[{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"outlook_message_send","arguments":{}}}]]"#;

        let result = service
            .evaluate(&evaluation(body), &service_policy(&service))
            .0;

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

        let result = service
            .evaluate(&evaluation(b"plain text"), &service_policy(&service))
            .0;

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
            let result = service.evaluate(&request, &service_policy(&service)).0;
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
            let result = service
                .evaluate(&evaluation(b"plain text"), &service_policy(&service))
                .0;
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

        let result = service
            .evaluate(&evaluation(b"plain text"), &service_policy(&service))
            .0;

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

        let result = service
            .evaluate(&evaluation(b"plain text"), &service_policy(&service))
            .0;

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

/// Egress decision recording, observed through the real emitter.
///
/// The other test module runs with the sink disabled, so nothing there can see
/// what a decision records. These drive the real handler and read the JSONL
/// back, which is the only way a wrong decision or a lost record is visible.
#[cfg(test)]
mod egress_audit_tests {
    use super::tests::{
        StubEvaluator, audit_records, authenticated_request, evaluation, make_audited_service,
        make_authenticated_audited_service,
    };
    use super::*;
    use apf_policy_eval::{Finding as EvalFinding, Severity as EvalSeverity};

    async fn decide(evaluator: StubEvaluator, dir: &std::path::Path) -> wire::HttpRequestResult {
        make_audited_service(evaluator, dir)
            .evaluate_http_request(Request::new(evaluation(b"{}")))
            .await
            .expect("middleware answers")
            .into_inner()
    }

    /// An allowed request must name the policy that allowed it and the sandbox
    /// it came from, and must not claim a human identity OpenShell never
    /// established.
    #[tokio::test]
    async fn an_allowed_request_is_recorded_against_the_deciding_policy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = decide(StubEvaluator::returning(EvalResult::default()), dir.path()).await;
        assert_eq!(result.decision, wire::Decision::Allow as i32);

        let records = audit_records(dir.path());
        assert_eq!(records.len(), 1, "exactly one record per decision");
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(r.decision, Some(apf_audit::Decision::Allow));
        assert_eq!(r.reason_code.as_deref(), Some("middleware.allowed"));
        assert_eq!(
            r.verb.as_deref(),
            Some("http.post"),
            "the raw method does not satisfy the verb profile"
        );
        let resource = r.resource.as_ref().expect("resource recorded");
        assert_eq!(resource.id, "api.example.com");
        assert_eq!(r.bundle_digest.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(r.policy_revision, Some(7));
        assert_eq!(
            r.correlation_id, "request-017",
            "the wire's request id is what joins this record to the supervisor's log"
        );
        assert!(
            r.error_info.is_none(),
            "an allow carries no denial explanation: {:?}",
            r.error_info
        );
        assert_eq!(r.session_id.as_deref(), Some("sandbox-042"));
        assert_eq!(
            r.user_id, None,
            "OpenShell V1 has no user subject; the sandbox is not one"
        );
    }

    /// The record must name the tool the decision was about: on the MCP path
    /// every request is a POST to the same front, and without the tool every
    /// record reads identically.
    #[tokio::test]
    async fn an_mcp_tool_call_records_the_tool_as_the_verb() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        let result = service
            .evaluate_http_request(Request::new(evaluation(super::tests::MCP_FIXTURE)))
            .await
            .expect("middleware answers")
            .into_inner();
        assert_eq!(result.decision, wire::Decision::Allow as i32);

        let records = audit_records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(
            r.verb.as_deref(),
            Some("tool.outlook_message_send"),
            "the governed action was a tool invocation, not a bare POST"
        );
        assert_eq!(
            r.resource.as_ref().expect("resource").id,
            "api.example.com",
            "the L4 host stays on the record"
        );
    }

    /// A tool name the agent chooses must not be able to strip the record:
    /// coercion pins it to the verb profile before validation ever sees it.
    #[tokio::test]
    async fn a_hostile_tool_name_cannot_strip_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Sk-EVIL ../;drop name","arguments":{}}}"#;
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        let result = service
            .evaluate_http_request(Request::new(evaluation(body)))
            .await
            .expect("middleware answers")
            .into_inner();
        assert_eq!(result.decision, wire::Decision::Allow as i32);

        let records = audit_records(dir.path());
        assert_eq!(records.len(), 1, "the request must still leave a record");
        assert_eq!(
            records[0].verb.as_deref(),
            Some("tool.k.dropname"),
            "the hostile name survives only in coerced form"
        );
    }

    /// A hostname the agent chooses must not be able to strip the record. The
    /// value coerces cleanly but trips the sanitizer, so this is the degrade
    /// path — the one the whole design rests on, and previously untested.
    #[tokio::test]
    async fn a_hostile_hostname_degrades_the_record_rather_than_erasing_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut eval = evaluation(b"{}");
        if let Some(target) = eval.target.as_mut() {
            // Three dot-separated base64url runs: a legal DNS name that reads
            // as a JWT to the sanitizer.
            target.host = "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccc".to_string();
        }
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        let result = service
            .evaluate_http_request(Request::new(eval))
            .await
            .expect("middleware answers")
            .into_inner();
        assert_eq!(result.decision, wire::Decision::Allow as i32);

        let records = audit_records(dir.path());
        assert_eq!(records.len(), 1, "the request must still leave a record");
        let r = &records[0];
        assert_eq!(
            r.decision,
            Some(apf_audit::Decision::Allow),
            "an allowed request must never read as blocked"
        );
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied request detail omitted"),
            "the record must mark itself as degraded"
        );
    }

    /// A policy is free to define a real finding of the stand-in's kind. It
    /// must not be read as a verdict, and must survive into the record — the
    /// count-based strip is what makes that possible.
    #[tokio::test]
    async fn a_real_policy_verdict_finding_is_not_mistaken_for_the_stand_in() {
        let dir = tempfile::tempdir().expect("temp dir");
        let r = decide(
            StubEvaluator::returning(EvalResult {
                allow: false,
                deny_reason: "blocked".to_string(),
                findings: vec![EvalFinding {
                    kind: "policy_verdict".to_string(),
                    label: "escalate".to_string(),
                    severity: EvalSeverity::Low,
                    confidence: None,
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;
        assert_eq!(r.decision, wire::Decision::Deny as i32);

        let record = &audit_records(dir.path())[0];
        assert_eq!(
            record.verdict, None,
            "the evaluator raised no signal, so none is recorded"
        );
        assert!(
            record
                .findings
                .as_ref()
                .is_some_and(|f| f.iter().any(|x| x.kind == "policy_verdict")),
            "a policy-defined finding must survive: {:?}",
            record.findings
        );
    }

    /// The allow path with both a real finding and a non-default verdict: the
    /// stand-in is present here, so this is where the count-based strip has to
    /// pick the right element.
    #[tokio::test]
    async fn an_allow_keeps_a_real_finding_beside_the_lifted_verdict() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                verdict: Verdict::Warn,
                findings: vec![EvalFinding {
                    kind: "content.class".to_string(),
                    label: "pii".to_string(),
                    severity: EvalSeverity::Medium,
                    confidence: None,
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.verdict, Some(apf_audit::Verdict::Warn));
        let findings = r.findings.as_ref().expect("the real finding survives");
        assert_eq!(findings.len(), 1, "the stand-in must not be recorded too");
        assert_eq!(findings[0].label, "pii");
        assert_eq!(
            r.reason_code.as_deref(),
            Some("middleware.allowed_with_findings")
        );
    }

    /// The redaction case: a secret was found, the body was rewritten, and the
    /// sanitised request went through. Without the effect the record reads as
    /// "found a critical secret and allowed it anyway".
    #[tokio::test]
    async fn a_replaced_body_is_recorded_as_an_effect() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                body_replacement: Some(r#"{"apf_redacted":true}"#.to_string()),
                findings: vec![EvalFinding {
                    kind: "secret_detected".to_string(),
                    label: "openai_key".to_string(),
                    severity: EvalSeverity::Critical,
                    confidence: None,
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.decision, Some(apf_audit::Decision::Allow));
        let effects = r.effects.as_ref().expect("the rewrite is recorded");
        assert_eq!(
            effects.payload_replaced,
            Some(true),
            "the request upstream received was not the one sent"
        );
    }

    /// `apply_effects` returns final bytes for both a wholesale replacement and
    /// a targeted patch, so the wire cannot tell them apart. Recording a patch
    /// as `payload_replaced` claims the whole body was swapped when one field
    /// was edited — and the operand must never reach the record.
    #[tokio::test]
    async fn a_targeted_patch_records_as_a_patch_not_a_replacement() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                body_patches: vec![apf_policy_eval::JsonPatch {
                    op: apf_policy_eval::PatchOp::Add,
                    path: "/content".to_string(),
                    value: Some(serde_json::json!("sk-not-a-real-key-000000")),
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        let effects = r.effects.as_ref().expect("the patch is recorded");
        assert_eq!(
            effects.payload_replaced, None,
            "a patch is not a wholesale replacement"
        );
        assert_eq!(effects.patch_count, Some(1));
        assert_eq!(effects.patches[0].path, "/content");
        assert_eq!(effects.patches[0].op, apf_audit::PatchOp::Add);

        let line =
            std::fs::read_to_string(dir.path().join("apf-policy-gateway-middleware-audit.jsonl"))
                .expect("audit file");
        assert!(
            !line.contains("sk-not-a-real-key"),
            "the patch operand must never reach the record: {line}"
        );
    }

    /// Each action must round-trip its own way. Recording an append as a set,
    /// or a removal as a write, says the request was changed differently than
    /// it was.
    #[tokio::test]
    async fn each_header_action_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                header_mutations: vec![
                    apf_policy_eval::HeaderMutation {
                        name: "x-openshell-middleware-added".to_string(),
                        action: apf_policy_eval::HeaderAction::Add,
                        value: Some("v".to_string()),
                    },
                    apf_policy_eval::HeaderMutation {
                        name: "x-vendor-tracking".to_string(),
                        action: apf_policy_eval::HeaderAction::Remove,
                        value: None,
                    },
                ],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        let m = &r
            .effects
            .as_ref()
            .expect("mutations recorded")
            .header_mutations;
        assert_eq!(m.len(), 2, "order is preserved: {m:?}");
        assert_eq!(m[0].name, "x-openshell-middleware-added");
        assert_eq!(m[0].action, apf_audit::HeaderAction::Add);
        assert_eq!(m[1].name, "x-vendor-tracking");
        assert_eq!(m[1].action, apf_audit::HeaderAction::Remove);
    }

    /// An ordinary header name can read as a credential — `task-classification`
    /// contains `sk-`. The guard scans substrings, so recording it would drop
    /// the whole record. The mutation goes, the record stays.
    #[tokio::test]
    async fn a_credential_shaped_header_name_does_not_degrade_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                header_mutations: vec![apf_policy_eval::HeaderMutation {
                    name: "x-openshell-middleware-task-classification-id".to_string(),
                    action: apf_policy_eval::HeaderAction::Set,
                    value: Some("v".to_string()),
                }],
                body_replacement: Some(r#"{"redacted":true}"#.to_string()),
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.reason, None, "the record must not degrade");
        assert_eq!(
            r.resource.as_ref().map(|res| res.id.as_str()),
            Some("api.example.com"),
            "host survives"
        );
        let effects = r.effects.as_ref().expect("the replacement still records");
        assert_eq!(effects.payload_replaced, Some(true));
        assert!(
            effects.header_mutations.is_empty(),
            "the unrecordable name is dropped, not the record: {effects:?}"
        );
    }

    /// A degraded record still has to say the body was rewritten. Dropping the
    /// effect there would turn the one record proving redaction worked into a
    /// bare allow — the worst reading, on the least legible record.
    #[tokio::test]
    async fn a_degraded_record_keeps_the_payload_replacement() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut eval = evaluation(b"{}");
        if let Some(target) = eval.target.as_mut() {
            // Reads as a JWT to the sanitizer, forcing the fallback.
            target.host = "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccc".to_string();
        }
        let service = make_audited_service(
            StubEvaluator::returning(EvalResult {
                body_replacement: Some(r#"{"redacted":true}"#.to_string()),
                header_mutations: vec![apf_policy_eval::HeaderMutation {
                    name: "x-openshell-middleware-trace".to_string(),
                    action: apf_policy_eval::HeaderAction::Set,
                    value: Some("v".to_string()),
                }],
                ..Default::default()
            }),
            dir.path(),
        );
        service
            .evaluate_http_request(Request::new(eval))
            .await
            .expect("middleware answers");

        let r = &audit_records(dir.path())[0];
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied request detail omitted"),
            "this must be the degraded record"
        );
        let effects = r
            .effects
            .as_ref()
            .expect("the rewrite survives degradation");
        assert_eq!(effects.payload_replaced, Some(true));
        assert!(
            effects.header_mutations.is_empty(),
            "policy-authored names are dropped on the retry: {effects:?}"
        );
    }

    /// When the only mutation is unrecordable and nothing else was applied, the
    /// field must vanish entirely. An `effects: {}` fails the schema `anyOf`
    /// and would take the whole record down — the opposite of the intent.
    #[tokio::test]
    async fn dropping_the_only_mutation_omits_effects_entirely() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                header_mutations: vec![apf_policy_eval::HeaderMutation {
                    name: "x-openshell-middleware-task-classification-id".to_string(),
                    action: apf_policy_eval::HeaderAction::Set,
                    value: Some("v".to_string()),
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.reason, None, "the record must not degrade");
        assert!(
            r.effects.is_none(),
            "nothing recordable was applied: {:?}",
            r.effects
        );
    }

    /// Patch paths are policy-authored strings and reach the record exactly as
    /// header names do — long, or credential-shaped by accident. `/sk-config/`
    /// is a plausible pointer whose `sk-` prefix the guard reads as a key.
    #[tokio::test]
    async fn unrecordable_patch_paths_do_not_degrade_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                body_patches: vec![
                    apf_policy_eval::JsonPatch {
                        op: apf_policy_eval::PatchOp::Add,
                        path: "/sk-configuration-values-name".to_string(),
                        value: Some(serde_json::json!("x")),
                    },
                    apf_policy_eval::JsonPatch {
                        op: apf_policy_eval::PatchOp::Add,
                        path: format!("/{}", "p".repeat(400)),
                        value: Some(serde_json::json!("x")),
                    },
                ],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.reason, None, "the record must not degrade");
        let effects = r.effects.as_ref().expect("the patches are recorded");
        assert_eq!(
            effects.patch_count,
            Some(2),
            "the count stays exact even when a path cannot be carried"
        );
        // The credential-shaped one is dropped; the long one is truncated.
        assert_eq!(effects.patches.len(), 1, "{:?}", effects.patches);
        assert_eq!(effects.patches[0].path.chars().count(), 256);
    }

    /// `replace` says a field was redacted in altered form; `remove` says it is
    /// gone. Recording one as the other misstates what left the sandbox.
    #[tokio::test]
    async fn each_patch_op_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                body_patches: vec![
                    apf_policy_eval::JsonPatch {
                        op: apf_policy_eval::PatchOp::Add,
                        path: "/added".to_string(),
                        value: Some(serde_json::json!("x")),
                    },
                    apf_policy_eval::JsonPatch {
                        op: apf_policy_eval::PatchOp::Replace,
                        path: "/added".to_string(),
                        value: Some(serde_json::json!("y")),
                    },
                    apf_policy_eval::JsonPatch {
                        op: apf_policy_eval::PatchOp::Remove,
                        path: "/added".to_string(),
                        value: None,
                    },
                ],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        let p = &r.effects.as_ref().expect("patches recorded").patches;
        assert_eq!(p.len(), 3, "order is preserved: {p:?}");
        assert_eq!(p[0].op, apf_audit::PatchOp::Add);
        assert_eq!(p[1].op, apf_audit::PatchOp::Replace);
        assert_eq!(p[2].op, apf_audit::PatchOp::Remove);
    }

    /// A degraded record must still say the body was patched. `patch_count` is
    /// an integer, so unlike the paths it cannot be what tripped the guard.
    #[tokio::test]
    async fn a_degraded_record_keeps_the_patch_count() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut eval = evaluation(b"{}");
        if let Some(target) = eval.target.as_mut() {
            target.host = "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccc".to_string();
        }
        let service = make_audited_service(
            StubEvaluator::returning(EvalResult {
                body_patches: vec![apf_policy_eval::JsonPatch {
                    op: apf_policy_eval::PatchOp::Add,
                    path: "/content".to_string(),
                    value: Some(serde_json::json!("redacted")),
                }],
                ..Default::default()
            }),
            dir.path(),
        );
        service
            .evaluate_http_request(Request::new(eval))
            .await
            .expect("middleware answers");

        let r = &audit_records(dir.path())[0];
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied request detail omitted"),
            "this must be the degraded record"
        );
        let effects = r
            .effects
            .as_ref()
            .expect("the patching survives degradation");
        assert_eq!(effects.patch_count, Some(1));
        assert!(
            effects.patches.is_empty(),
            "paths are strings and go: {effects:?}"
        );
    }

    /// A plain allow changed nothing, and an empty `effects` object would read
    /// as "we modified something" to anyone filtering on the field.
    #[tokio::test]
    async fn an_untouched_request_records_no_effects() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(StubEvaluator::returning(EvalResult::default()), dir.path()).await;

        let r = &audit_records(dir.path())[0];
        assert!(r.effects.is_none(), "nothing was applied: {:?}", r.effects);
    }

    /// Header names are recorded so a reader can see what was rewritten; values
    /// are not, because that is where a policy would put a token.
    #[tokio::test]
    async fn header_mutations_record_names_and_actions_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                header_mutations: vec![apf_policy_eval::HeaderMutation {
                    name: "x-openshell-middleware-trace".to_string(),
                    action: apf_policy_eval::HeaderAction::Set,
                    value: Some("sk-not-a-real-key-000000".to_string()),
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        let effects = r.effects.as_ref().expect("the mutation is recorded");
        assert_eq!(effects.header_mutations.len(), 1);
        assert_eq!(
            effects.header_mutations[0].name,
            "x-openshell-middleware-trace"
        );
        assert_eq!(
            effects.header_mutations[0].action,
            apf_audit::HeaderAction::Set,
            "an overwrite is not an append"
        );
        let line =
            std::fs::read_to_string(dir.path().join("apf-policy-gateway-middleware-audit.jsonl"))
                .expect("audit file");
        assert!(
            !line.contains("sk-not-a-real-key"),
            "the header value must never reach the record: {line}"
        );
    }

    /// The wire validator bounds all names and values together, not each name,
    /// so a long header name reaches the record. Over the schema cap the whole
    /// record degrades — losing host, verb and findings over a header.
    #[tokio::test]
    async fn a_long_header_name_does_not_degrade_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let name = format!("x-openshell-middleware-{}", "n".repeat(400));
        decide(
            StubEvaluator::returning(EvalResult {
                header_mutations: vec![apf_policy_eval::HeaderMutation {
                    name,
                    action: apf_policy_eval::HeaderAction::Set,
                    value: Some("v".to_string()),
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(
            r.reason, None,
            "a long header name must not force the fallback"
        );
        assert_eq!(
            r.resource.as_ref().map(|res| res.id.as_str()),
            Some("api.example.com"),
            "the whole record survives, not just the effect"
        );
        let effects = r.effects.as_ref().expect("the mutation is recorded");
        assert_eq!(effects.header_mutations[0].name.chars().count(), 256);
    }

    /// The refusal happens in `authorize`, so nothing downstream sees it. Left
    /// unwired, a caller probing an RPC it may not call leaves no trace.
    #[tokio::test]
    async fn a_caller_refused_for_this_rpc_is_recorded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service = make_authenticated_audited_service(
            StubEvaluator::returning(EvalResult::default()),
            dir.path(),
        );
        // ValidateConfig is a gateway RPC; a supervisor is authenticated but
        // not permitted.
        let request = authenticated_request(
            wire::ValidateConfigRequest::default(),
            ExtensionCallerKind::Supervisor,
            Some("sandbox-1"),
        );
        assert!(
            service.validate_config(request).await.is_err(),
            "a supervisor must not reach ValidateConfig"
        );

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authentication);
        assert_eq!(
            r.reason_code.as_deref(),
            Some("extension_auth.caller_not_allowed")
        );
        assert_eq!(r.caller_kind.as_deref(), Some("supervisor"));
    }

    /// A request with no verified caller at all — a runtime wrapping the
    /// service without the verifier. It must fail closed and say so.
    #[tokio::test]
    async fn an_unauthenticated_caller_is_recorded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service = make_authenticated_audited_service(
            StubEvaluator::returning(EvalResult::default()),
            dir.path(),
        );
        assert!(
            service
                .evaluate_http_request(Request::new(evaluation(b"{}")))
                .await
                .is_err(),
            "no caller means no dispatch"
        );

        let r = &audit_records(dir.path())[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("extension_auth.caller_unauthenticated")
        );
        assert_eq!(
            r.caller_kind, None,
            "nothing authenticated, so no kind is named"
        );
    }

    /// A caller-chosen sandbox id must not be able to erase the record of its
    /// own impersonation attempt.
    #[tokio::test]
    async fn a_hostile_claimed_sandbox_id_cannot_erase_the_mismatch_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        service.record_binding_mismatch(&BindingMismatch {
            bound_sandbox: "sandbox-bound",
            claimed_sandbox: "AKIAIOSFODNN7EXAMPLE",
        });

        let records = audit_records(dir.path());
        assert_eq!(records.len(), 1, "the attempt must still be recorded");
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authentication);
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied sandbox ids omitted"),
            "degraded rather than lost"
        );
    }

    /// The denial's explanation must reach the record's `error`, or every
    /// egress block reads the same.
    #[tokio::test]
    async fn a_substrate_denial_keeps_the_policy_explanation() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                allow: false,
                deny_reason: "egress to an unapproved host".to_string(),
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(r.decision, Some(apf_audit::Decision::Deny));
        assert!(
            r.error_info
                .as_ref()
                .is_some_and(|e| e.message.contains("unapproved host")
                    && e.code == "middleware.policy_denied"),
            "without it every egress block reads the same: {:?}",
            r.error_info
        );
        assert_eq!(
            r.reason, None,
            "`reason` belongs to the degradation marker alone now"
        );
    }

    /// A degraded policy denial must still read as one: a rule keyed on the
    /// `middleware.policy_denied` reason code would otherwise miss exactly the
    /// records an attacker can force.
    #[tokio::test]
    async fn a_degraded_substrate_denial_keeps_its_type() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut eval = evaluation(b"{}");
        if let Some(target) = eval.target.as_mut() {
            target.host = "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccc".to_string();
        }
        let service = make_audited_service(
            StubEvaluator::returning(EvalResult {
                allow: false,
                deny_reason: "blocked".to_string(),
                ..Default::default()
            }),
            dir.path(),
        );
        service
            .evaluate_http_request(Request::new(eval))
            .await
            .expect("middleware answers");

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(
            r.decision,
            Some(apf_audit::Decision::Deny),
            "the denial must survive degradation"
        );
        assert_eq!(
            r.reason_code.as_deref(),
            Some("middleware.policy_denied"),
            "the substrate-vs-policy distinction lives here now"
        );
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied request detail omitted")
        );
    }

    /// One sandbox using a credential bound to another is the highest-value
    /// event this seam sees, and it is refused before any policy runs.
    #[tokio::test]
    async fn a_sandbox_binding_mismatch_is_recorded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        service.record_binding_mismatch(&BindingMismatch {
            bound_sandbox: "sandbox-bound",
            claimed_sandbox: "sandbox-claimed",
        });

        let r = &audit_records(dir.path())[0];
        // Typed as an authentication refusal, not an egress denial: modelling
        // it as a deny would bury an impersonation probe in policy traffic.
        assert_eq!(r.event_type, apf_audit::EventType::Authentication);
        assert_eq!(
            r.reason_code.as_deref(),
            Some("extension_auth.sandbox_binding_mismatch")
        );
        // Both ids in typed fields, so hostile input cannot strip them out of
        // a free-text sentence.
        assert_eq!(r.caller_sandbox_id.as_deref(), Some("sandbox-bound"));
        assert_eq!(r.claimed_sandbox_id.as_deref(), Some("sandbox-claimed"));
        assert_eq!(
            r.bundle_digest, None,
            "no policy was consulted, so the record names none"
        );
    }

    /// The schema leaves this field unpatterned deliberately. Coercing it would
    /// let `#sandbox-042` record as `sandbox-042` — a claim on a real sandbox,
    /// indistinguishable from a genuine one.
    #[tokio::test]
    async fn a_claimed_sandbox_id_is_recorded_as_claimed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        service.record_binding_mismatch(&BindingMismatch {
            bound_sandbox: "sandbox-bound",
            claimed_sandbox: "#sandbox-042",
        });

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.claimed_sandbox_id.as_deref(), Some("#sandbox-042"));
        assert_eq!(
            r.reason, None,
            "a legal-but-unusual id is not a degraded record"
        );
    }

    /// An absent context must not cost the authenticated half of the record.
    /// Both ids are `minLength: 1`, so an empty claim fails validation and takes
    /// the bound id down with it unless the sentinel stands in.
    #[tokio::test]
    async fn an_empty_claimed_sandbox_id_keeps_the_authenticated_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let service =
            make_audited_service(StubEvaluator::returning(EvalResult::default()), dir.path());
        service.record_binding_mismatch(&BindingMismatch {
            bound_sandbox: "sandbox-bound",
            claimed_sandbox: "",
        });

        let r = &audit_records(dir.path())[0];
        assert_eq!(
            r.caller_sandbox_id.as_deref(),
            Some("sandbox-bound"),
            "the verified id is the one value here that is not caller-chosen"
        );
        assert_eq!(r.claimed_sandbox_id.as_deref(), Some("unspecified"));
        assert_eq!(r.reason, None, "the record is whole, not degraded");
    }

    /// A blocked request must record as blocked, carrying the policy's reason
    /// and the observations behind it. A deny recorded as an allow would say
    /// egress happened when it did not.
    #[tokio::test]
    async fn a_denied_request_is_recorded_as_a_denial_with_its_findings() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = decide(
            StubEvaluator::returning(EvalResult {
                allow: false,
                deny_reason: "egress to an unapproved host".to_string(),
                findings: vec![EvalFinding {
                    kind: "content.class".to_string(),
                    label: "AWS access key".to_string(),
                    severity: EvalSeverity::High,
                    confidence: Some(91),
                }],
                ..Default::default()
            }),
            dir.path(),
        )
        .await;
        assert_eq!(result.decision, wire::Decision::Deny as i32);

        let r = &audit_records(dir.path())[0];
        // The substrate-vs-PDP distinction lives in the reason_code, and this
        // code is the substrate's alone.
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(r.reason_code.as_deref(), Some("middleware.policy_denied"));
        let findings = r.findings.as_ref().expect("findings carried");
        assert_eq!(findings[0].label, "AWS access key", "recorded verbatim");
        assert_eq!(findings[0].confidence, Some(91));
    }

    /// The wire carries the verdict as a synthetic finding because it has no
    /// verdict field. Audit has one, so it must be lifted rather than left to
    /// masquerade as an observation.
    #[tokio::test]
    async fn an_advisory_verdict_is_lifted_out_of_the_findings() {
        let dir = tempfile::tempdir().expect("temp dir");
        decide(
            StubEvaluator::returning(EvalResult {
                verdict: Verdict::Escalate,
                ..Default::default()
            }),
            dir.path(),
        )
        .await;

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.verdict, Some(apf_audit::Verdict::Escalate));
        assert_eq!(
            r.reason_code.as_deref(),
            Some("middleware.allowed"),
            "the stand-in is not an observation, so this allow carries none"
        );
        assert!(
            r.findings
                .as_ref()
                .is_none_or(|f| f.iter().all(|x| x.kind != "policy_verdict")),
            "the stand-in must not be recorded as an observation too"
        );
    }

    /// The evaluator failing is a hard deny, and it is the case where a missing
    /// record would hide that policy never ran.
    #[tokio::test]
    async fn a_failed_evaluation_is_recorded_as_a_denial() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = decide(StubEvaluator::failing(), dir.path()).await;
        assert_eq!(result.decision, wire::Decision::Deny as i32);

        let r = &audit_records(dir.path())[0];
        assert_eq!(r.decision, Some(apf_audit::Decision::Deny));
        assert_eq!(
            r.reason_code.as_deref(),
            Some("middleware.evaluation_failed")
        );
    }
}
