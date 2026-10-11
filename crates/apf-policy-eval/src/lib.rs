// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy evaluation backends for APF request decisions.
//!
//! [`CedarEvaluator`] compiles `PolicyRule` documents into Cedar policy sets.
//! Each call to [`Evaluator::evaluate`] checks one request and returns an
//! allow/deny decision.
//!
//! The [`Evaluator`] trait abstracts the evaluation backend — a new engine is
//! `impl Evaluator for <NewEngine>` with no other changes required.
//!
//! Before the engine runs, the [`pipeline`] enrichment stage may populate
//! [`EvalInput::context_attributes`] from policy information providers. The
//! engine adapter exposes those namespaces to policy; the stage itself is
//! independent of the policy language.

use std::collections::BTreeMap;

use serde_json::Value;

pub mod apply;
pub mod cedar;
pub mod pipeline;

pub use apply::{AppliedRequest, ApplyError, apply_effects};
pub use cedar::{
    AnnotationOp, AnnotationOutput, AnnotationRule, AnnotationSpec, AnnotatorEngine, BodySpec,
    CedarEvaluator, EffectEngine, FindingSpec, HeaderSpec, InlineFindingSpec, PatchSpec,
    PolicyAnnotatorDoc, PolicyEffectDoc, PolicyFindingDoc, PolicyRuleDoc, PolicyRuleRole,
    SetTrueIf, SetValueFrom,
};
pub use pipeline::{
    ContextEnricher, EnrichFuture, EnrichmentError, Evaluation, ProviderOutcome, ProviderStatus,
    decide, enrich_or_deny,
};

/// Context roots owned by the request adapters and the engine. A provider
/// namespace can never use one of these names.
pub const RESERVED_CONTEXT_ROOTS: &[&str] = &[
    "args",
    "annotations",
    "data",
    "body_text",
    "has_tool_name",
    "target_host",
    "target_method",
    "target_path",
    "target_scheme",
];

/// Action id for a request that carries neither a tool nor a capability.
pub const ACTION_INVOKE: &str = "invoke";

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Input to a single policy decision.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EvalInput {
    /// Tool name — maps to `resource.class` on the wire. `None` when the
    /// request carries no tool identity (e.g. non-MCP traffic).
    pub tool: Option<String>,
    /// Capability name — maps to `verb` on the wire. `None` when the request
    /// carries no capability.
    pub capability: Option<String>,
    /// Authenticated subject from the bound handle.
    pub user_subject: String,
    /// Call arguments from the request.
    pub args: serde_json::Map<String, Value>,
    /// Request body as text; wire adapters may use lossy UTF-8 so decodable
    /// content remains visible when an otherwise binary body is received.
    pub body_text: String,
    /// Parsed request body when it is JSON, `None` otherwise.
    pub body_json: Option<Value>,
    /// HTTP target metadata; `None` for the direct Authorize path.
    pub target: Option<RequestTarget>,
    /// Derived from `tool.is_some()` by the constructors.
    pub has_tool_name: bool,
    /// Attributes supplied by policy information providers, keyed by
    /// namespace domain. Each record holds the provider's claims plus the
    /// `_meta` provenance record the enrichment stage writes. Only that stage
    /// populates this map; adapters leave it empty.
    pub context_attributes: BTreeMap<String, serde_json::Map<String, Value>>,
    /// Runtime instance the request originates from, when the adapter
    /// established one.
    pub runtime: Option<RuntimeIdentity>,
}

impl EvalInput {
    /// Build an input for a tool-call decision, deriving `has_tool_name` and
    /// defaulting the body and target fields.
    #[must_use]
    pub fn for_tool_call(
        tool: Option<String>,
        capability: Option<String>,
        user_subject: String,
        args: serde_json::Map<String, Value>,
    ) -> Self {
        Self {
            has_tool_name: tool.is_some(),
            tool,
            capability,
            user_subject,
            args,
            ..Self::default()
        }
    }

    /// Normalized action id: `<tool>::<capability>`, the tool alone when the
    /// request carries no capability, or [`ACTION_INVOKE`] when it carries
    /// neither. Engine adapters and provider triggers use the same value.
    #[must_use]
    pub fn action_id(&self) -> String {
        match (&self.tool, &self.capability) {
            (Some(tool), Some(capability)) => format!("{tool}::{capability}"),
            (Some(tool), None) => tool.clone(),
            _ => ACTION_INVOKE.to_string(),
        }
    }
}

/// The workload instance a request originates from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeIdentity {
    /// Runtime substrate, e.g. `openshell`.
    pub platform: String,
    /// Stable instance identifier within the platform, e.g. a sandbox id.
    pub instance_id: String,
    /// Agent type running in the instance, when known.
    pub agent_type: Option<String>,
    /// How `instance_id` was established.
    pub attestation: RuntimeAttestation,
}

/// How a runtime instance identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAttestation {
    /// Asserted by the calling enforcement point.
    Caller,
    /// Bound to the OpenShell supervisor's authenticated token.
    OpenshellSupervisorJwt,
}

impl RuntimeAttestation {
    /// Stable name used on the wire and in audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::OpenshellSupervisorJwt => "openshell-supervisor-jwt",
        }
    }
}

/// HTTP target metadata for a proxied request.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestTarget {
    pub host: String,
    pub method: String,
    pub path: String,
    pub scheme: String,
}

/// Result of evaluating one request against the loaded grants.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalResult {
    /// `true` → allow; `false` → deny.
    pub allow: bool,
    /// Human-readable reason for a denial (empty on allow).
    pub deny_reason: String,
    /// Advisory signal accompanying an allow. Meaningless on deny.
    pub verdict: Verdict,
    /// Machine-readable reason for a non-default verdict.
    pub reason: Option<String>,
    /// Human-readable detail for a non-default verdict.
    pub message: Option<String>,
    /// RFC 6902 operations to apply to the request body.
    pub body_patches: Vec<JsonPatch>,
    /// Full body replacement; takes precedence over `body_patches`.
    pub body_replacement: Option<String>,
    /// Header mutations to apply to the request.
    pub header_mutations: Vec<HeaderMutation>,
    /// Observations attached to the decision (e.g. detected content classes).
    pub findings: Vec<Finding>,
}

impl Default for EvalResult {
    /// A plain allow: no deny reason, no mutations, no findings.
    fn default() -> Self {
        Self {
            allow: true,
            deny_reason: String::new(),
            verdict: Verdict::Allow,
            reason: None,
            message: None,
            body_patches: Vec::new(),
            body_replacement: None,
            header_mutations: Vec::new(),
            findings: Vec::new(),
        }
    }
}

/// Advisory verdict attached to an allow decision. Ordered by severity so
/// concurrent effects aggregate to the strongest signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Verdict {
    #[default]
    Allow,
    Warn,
    Escalate,
}

/// A single RFC 6902 JSON Patch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPatch {
    pub op: PatchOp,
    pub path: String,
    /// Operand for `Replace`/`Add`; `None` for `Remove`.
    pub value: Option<Value>,
}

/// JSON Patch operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    Replace,
    Add,
    Remove,
}

/// A single header mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMutation {
    pub name: String,
    pub action: HeaderAction,
    /// Operand for `Set`/`Add`; `None` for `Remove`.
    pub value: Option<String>,
}

/// Header mutation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAction {
    Set,
    Add,
    Remove,
}

/// An observation emitted alongside a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Finding category (e.g. content class or detector name).
    pub kind: String,
    /// Specific label within the category.
    pub label: String,
    pub severity: Severity,
    /// Detector confidence in percent, when available.
    pub confidence: Option<u8>,
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Errors returned by evaluator implementations.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("evaluator engine error: {0}")]
    Engine(String),
    #[error("evaluator lock poisoned")]
    Poisoned,
}

/// An evaluator together with the identity of the policy it was built from.
///
/// Lives here rather than in a consumer because every enforcement point that
/// holds an evaluator needs to name the policy behind its decisions, and the
/// two must travel as one value: read separately, a hot-swap between the two
/// reads lets a record name a policy other than the one that decided.
pub struct ActivePolicy {
    pub evaluator: std::sync::Arc<dyn Evaluator>,
    /// Digest of the document this evaluator was built from.
    pub bundle_digest: String,
    /// Ordering signal; identity is the digest.
    pub policy_revision: u64,
}

/// Evaluation backend. Implement this to substitute Rego with CEL, Cedar, or
/// any other policy engine without changing `RequestGuard` or other consumers.
pub trait Evaluator: Send + Sync {
    fn evaluate(&self, input: EvalInput) -> Result<EvalResult, EvalError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_tool_call_derives_has_tool_name_some() {
        let input = EvalInput::for_tool_call(
            Some("outlook".to_string()),
            Some("message_search".to_string()),
            "user@corp.com".to_string(),
            serde_json::Map::new(),
        );
        assert!(input.has_tool_name);
        assert_eq!(input.tool.as_deref(), Some("outlook"));
        assert!(input.body_text.is_empty());
        assert!(input.body_json.is_none());
        assert!(input.target.is_none());
    }

    #[test]
    fn for_tool_call_derives_has_tool_name_none() {
        let input = EvalInput::for_tool_call(
            None,
            Some("message_search".to_string()),
            "user@corp.com".to_string(),
            serde_json::Map::new(),
        );
        assert!(!input.has_tool_name);
        assert!(input.tool.is_none());
        assert!(input.context_attributes.is_empty());
        assert!(input.runtime.is_none());
    }

    #[test]
    fn action_id_normalizes_tool_and_capability() {
        let both = EvalInput::for_tool_call(
            Some("outlook".to_string()),
            Some("message_search".to_string()),
            String::new(),
            serde_json::Map::new(),
        );
        assert_eq!(both.action_id(), "outlook::message_search");
        let tool_only = EvalInput::for_tool_call(
            Some("outlook".to_string()),
            None,
            String::new(),
            serde_json::Map::new(),
        );
        assert_eq!(tool_only.action_id(), "outlook");
        let neither = EvalInput::for_tool_call(None, None, String::new(), serde_json::Map::new());
        assert_eq!(neither.action_id(), ACTION_INVOKE);
        let capability_only = EvalInput::for_tool_call(
            None,
            Some("message_search".to_string()),
            String::new(),
            serde_json::Map::new(),
        );
        assert_eq!(capability_only.action_id(), ACTION_INVOKE);
    }

    #[test]
    fn attestation_names_are_stable() {
        assert_eq!(RuntimeAttestation::Caller.as_str(), "caller");
        assert_eq!(
            RuntimeAttestation::OpenshellSupervisorJwt.as_str(),
            "openshell-supervisor-jwt"
        );
    }

    #[test]
    fn eval_result_default_is_plain_allow() {
        let result = EvalResult::default();
        assert!(result.allow);
        assert!(result.deny_reason.is_empty());
        assert_eq!(result.verdict, Verdict::Allow);
        assert!(result.reason.is_none());
        assert!(result.message.is_none());
        assert!(result.body_patches.is_empty());
        assert!(result.body_replacement.is_none());
        assert!(result.header_mutations.is_empty());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn verdict_orders_by_severity() {
        assert!(Verdict::Escalate > Verdict::Warn);
        assert!(Verdict::Warn > Verdict::Allow);
        assert_eq!(Verdict::default(), Verdict::Allow);
    }
}
