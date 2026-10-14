// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The enrichment stage: trigger matching, subject projection, fan-out to
//! providers within budgets, validation and provenance stamping.
//!
//! Every registered provider contributes exactly one outcome per evaluation.
//! A provider whose trigger does not match is stamped `not_applicable`;
//! every other provider is looked up concurrently, each lookup under the
//! provider's budget and the whole stage under the stage budget. A failure
//! follows the provider's failure mode, except that caller-attributable
//! failures and internal errors always deny.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apf_policy_eval::{
    ContextEnricher, EnrichFuture, EnrichmentError, EvalInput, ProviderOutcome, ProviderStatus,
};
use prost::Message as _;
use serde_json::{Map, Value, json};
use tokio::task::JoinSet;

use super::config::{
    ConfigError, EndpointKind, FailureMode, Limits, MAX_CORRELATION_ID_BYTES, MAX_IN_FLIGHT,
    ProviderKind, RegistryConfig, Trigger,
};
use super::grpc::GrpcTransport;
use super::http::HttpTransport;
use super::provider::{Lookup, LookupResult, MAX_MESSAGE_BYTES, ProviderError, ProviderTransport};
use super::subject::{self, SubjectPath};

/// One registered provider with its binding and constraints.
pub struct RegisteredProvider {
    pub name: String,
    /// Context namespace, carried on the wire and in audit as the domain.
    pub domain: String,
    pub transport: Arc<dyn ProviderTransport>,
    /// Whether the transport authenticates the provider: a verified peer UID
    /// on a Unix socket or mutual TLS on the contract. REST providers and
    /// plain HTTP to a loopback host do not.
    pub peer_authenticated: bool,
    pub budget: Duration,
    pub on_failure: FailureMode,
    pub trigger: Trigger,
    pub subject: Vec<SubjectPath>,
}

impl fmt::Debug for RegisteredProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredProvider")
            .field("name", &self.name)
            .field("domain", &self.domain)
            .field("peer_authenticated", &self.peer_authenticated)
            .field("budget", &self.budget)
            .field("on_failure", &self.on_failure)
            .field("trigger", &self.trigger)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Enriches evaluator inputs from the registered providers.
pub struct ProviderContextEnricher {
    providers: Vec<RegisteredProvider>,
    stage_budget: Duration,
}

impl fmt::Debug for ProviderContextEnricher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderContextEnricher")
            .field("providers", &self.providers)
            .field("stage_budget", &self.stage_budget)
            .finish()
    }
}

/// What one spawned lookup reports back.
struct Completed {
    index: usize,
    result: Result<LookupResult, ProviderError>,
    latency_ms: u64,
}

impl ProviderContextEnricher {
    /// Build the enricher from a validated registration file.
    ///
    /// # Errors
    ///
    /// Returns the first validation or transport construction error.
    pub fn from_config(config: &RegistryConfig, limits: &Limits) -> Result<Self, ConfigError> {
        config.validate(limits)?;
        let mut providers = Vec::with_capacity(config.providers.len());
        for entry in &config.providers {
            let (transport, peer_authenticated): (Arc<dyn ProviderTransport>, bool) =
                match entry.kind {
                    ProviderKind::Http => {
                        let source = entry.http_source(limits)?;
                        (Arc::new(HttpTransport::new(&entry.name, &source)?), false)
                    }
                    ProviderKind::Grpc => match entry.endpoint_kind()? {
                        EndpointKind::Unix(socket) => {
                            let peer_uid = entry
                                .endpoint
                                .peer_uid
                                .unwrap_or_else(|| nix::unistd::geteuid().as_raw());
                            (
                                Arc::new(for_provider(
                                    &entry.name,
                                    GrpcTransport::unix(socket, peer_uid, MAX_IN_FLIGHT),
                                )?),
                                true,
                            )
                        }
                        EndpointKind::Https(url) => (
                            Arc::new(for_provider(
                                &entry.name,
                                GrpcTransport::https(
                                    url.as_str(),
                                    entry.endpoint.tls.as_ref(),
                                    MAX_IN_FLIGHT,
                                ),
                            )?),
                            true,
                        ),
                        EndpointKind::HttpLoopback(url) => (
                            Arc::new(for_provider(
                                &entry.name,
                                GrpcTransport::https(url.as_str(), None, MAX_IN_FLIGHT),
                            )?),
                            false,
                        ),
                    },
                };
            providers.push(RegisteredProvider {
                name: entry.name.clone(),
                domain: entry.context.clone(),
                transport,
                peer_authenticated,
                budget: entry.budget(limits),
                on_failure: entry.on_failure,
                trigger: entry.trigger(),
                subject: entry.subject_paths(),
            });
        }
        Ok(Self::new(providers, limits.stage_budget))
    }

    /// Build the enricher from already constructed providers.
    #[must_use]
    pub fn new(providers: Vec<RegisteredProvider>, stage_budget: Duration) -> Self {
        Self {
            providers,
            stage_budget,
        }
    }

    /// Whether any provider is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Context namespaces the registered providers own.
    pub fn contexts(&self) -> impl Iterator<Item = &str> {
        self.providers
            .iter()
            .map(|provider| provider.domain.as_str())
    }

    /// Hard cap on the whole stage.
    #[must_use]
    pub fn stage_budget(&self) -> Duration {
        self.stage_budget
    }

    async fn run(
        &self,
        input: &mut EvalInput,
        correlation_id: Option<&str>,
    ) -> Result<Vec<ProviderOutcome>, EnrichmentError> {
        let correlation_id = correlation_id.unwrap_or_default();
        let action_id = input.action_id();
        let started = Instant::now();
        let mut outcomes: Vec<Option<ProviderOutcome>> = vec![None; self.providers.len()];
        let mut tasks = JoinSet::new();
        let mut pending: HashMap<tokio::task::Id, usize> = HashMap::new();

        for (index, provider) in self.providers.iter().enumerate() {
            if !provider.trigger.matches(&action_id, input.tool.as_deref()) {
                outcomes[index] = Some(stamp(
                    input,
                    provider,
                    Map::new(),
                    outcome(provider, ProviderStatus::NotApplicable),
                ));
                continue;
            }
            if correlation_id.len() > MAX_CORRELATION_ID_BYTES {
                tasks.abort_all();
                return Err(caller_fault(provider, &outcomes));
            }
            let projected = subject::project(input, &provider.subject);
            if projected.encoded_len() > MAX_MESSAGE_BYTES {
                tasks.abort_all();
                return Err(caller_fault(provider, &outcomes));
            }
            let transport = Arc::clone(&provider.transport);
            let budget = provider.budget;
            let lookup = Lookup {
                subject: projected,
                domain: provider.domain.clone(),
                correlation_id: correlation_id.to_owned(),
            };
            let handle = tasks.spawn(async move {
                let started = Instant::now();
                let result =
                    match tokio::time::timeout(budget, transport.lookup(lookup, budget)).await {
                        Ok(result) => result,
                        Err(_elapsed) => Err(ProviderError::Timeout),
                    };
                Completed {
                    index,
                    result,
                    latency_ms: millis(started.elapsed()),
                }
            });
            pending.insert(handle.id(), index);
        }

        let deadline = tokio::time::Instant::now() + self.stage_budget;
        while !pending.is_empty() {
            let joined = match tokio::time::timeout_at(deadline, tasks.join_next_with_id()).await {
                Ok(Some(joined)) => joined,
                Ok(None) => break,
                Err(_elapsed) => {
                    tasks.abort_all();
                    let latency_ms = millis(started.elapsed());
                    let mut late: Vec<usize> = pending.drain().map(|(_, index)| index).collect();
                    late.sort_unstable();
                    for index in late {
                        let provider = &self.providers[index];
                        let failed = ProviderOutcome {
                            latency_ms,
                            ..outcome(provider, ProviderStatus::Timeout)
                        };
                        outcomes[index] = Some(self.settle_failure(
                            input,
                            provider,
                            failed,
                            &ProviderError::Timeout,
                            &outcomes,
                        )?);
                    }
                    break;
                }
            };
            let completed = match joined {
                Ok((id, completed)) => {
                    pending.remove(&id);
                    completed
                }
                Err(join_error) => {
                    tasks.abort_all();
                    let index = pending.remove(&join_error.id());
                    let provider = index.map(|index| &self.providers[index]);
                    let name = provider.map_or("unknown", |provider| provider.name.as_str());
                    tracing::warn!(
                        provider = name,
                        error = %join_error,
                        "provider lookup task failed"
                    );
                    let mut gathered = collect(&outcomes);
                    if let Some(provider) = provider {
                        gathered.push(outcome(provider, ProviderStatus::Internal));
                    }
                    return Err(EnrichmentError {
                        provider: name.to_owned(),
                        status: ProviderStatus::Internal,
                        outcomes: gathered,
                    });
                }
            };
            let provider = &self.providers[completed.index];
            outcomes[completed.index] = Some(match completed.result {
                Ok(LookupResult::Found(attributes)) => {
                    let found = ProviderOutcome {
                        age_seconds: u64::from(attributes.age_seconds),
                        evidence_ref: attributes.evidence_ref.clone(),
                        latency_ms: completed.latency_ms,
                        ..outcome(provider, ProviderStatus::Found)
                    };
                    stamp(input, provider, attributes.claims, found)
                }
                Ok(LookupResult::NoData) => {
                    let no_data = ProviderOutcome {
                        latency_ms: completed.latency_ms,
                        ..outcome(provider, ProviderStatus::NoData)
                    };
                    stamp(input, provider, Map::new(), no_data)
                }
                Err(error) => {
                    let failed = ProviderOutcome {
                        latency_ms: completed.latency_ms,
                        ..outcome(provider, error.status())
                    };
                    match self.settle_failure(input, provider, failed, &error, &outcomes) {
                        Ok(degraded) => degraded,
                        Err(denied) => {
                            tasks.abort_all();
                            return Err(denied);
                        }
                    }
                }
            });
        }

        Ok(collect(&outcomes))
    }

    /// Apply the provider's failure mode: degrade by stamping provenance
    /// only, or deny. Caller faults deny whatever the mode says.
    fn settle_failure(
        &self,
        input: &mut EvalInput,
        provider: &RegisteredProvider,
        failed: ProviderOutcome,
        error: &ProviderError,
        outcomes: &[Option<ProviderOutcome>],
    ) -> Result<ProviderOutcome, EnrichmentError> {
        tracing::warn!(
            provider = %provider.name,
            domain = %provider.domain,
            status = failed.status.as_str(),
            latency_ms = failed.latency_ms,
            error = %error,
            "provider lookup failed"
        );
        if failed.status.is_caller_fault() || provider.on_failure == FailureMode::FailClosed {
            let mut gathered = collect(outcomes);
            gathered.push(failed.clone());
            return Err(EnrichmentError {
                provider: provider.name.clone(),
                status: failed.status,
                outcomes: gathered,
            });
        }
        let degraded = ProviderOutcome {
            degraded: true,
            ..failed
        };
        Ok(stamp(input, provider, Map::new(), degraded))
    }
}

impl ContextEnricher for ProviderContextEnricher {
    fn enrich<'a>(
        &'a self,
        input: &'a mut EvalInput,
        correlation_id: Option<&'a str>,
    ) -> EnrichFuture<'a> {
        Box::pin(self.run(input, correlation_id))
    }
}

/// Attribute a transport construction error to its provider.
fn for_provider<T>(name: &str, result: Result<T, ConfigError>) -> Result<T, ConfigError> {
    result.map_err(|error| match error {
        ConfigError::Invalid(reason) => ConfigError::Provider {
            provider: name.to_owned(),
            reason,
        },
        other => other,
    })
}

/// A baseline outcome for `provider` with `status`; callers override the
/// fields the lookup determined.
fn outcome(provider: &RegisteredProvider, status: ProviderStatus) -> ProviderOutcome {
    ProviderOutcome {
        provider: provider.name.clone(),
        domain: provider.domain.clone(),
        status,
        degraded: false,
        cached: false,
        age_seconds: 0,
        evidence_ref: None,
        latency_ms: 0,
    }
}

/// The request itself cannot be sent to the provider.
fn caller_fault(
    provider: &RegisteredProvider,
    outcomes: &[Option<ProviderOutcome>],
) -> EnrichmentError {
    tracing::warn!(
        provider = %provider.name,
        domain = %provider.domain,
        status = ProviderStatus::InvalidInput.as_str(),
        "evaluation input cannot be sent to the provider"
    );
    let mut gathered = collect(outcomes);
    gathered.push(outcome(provider, ProviderStatus::InvalidInput));
    EnrichmentError {
        provider: provider.name.clone(),
        status: ProviderStatus::InvalidInput,
        outcomes: gathered,
    }
}

/// Write the namespace record, claims plus `_meta`, into the input and log
/// the outcome.
fn stamp(
    input: &mut EvalInput,
    provider: &RegisteredProvider,
    mut claims: Map<String, Value>,
    outcome: ProviderOutcome,
) -> ProviderOutcome {
    claims.insert(
        "_meta".to_owned(),
        Value::Object(provenance(provider, &outcome)),
    );
    input
        .context_attributes
        .insert(provider.domain.clone(), claims);
    tracing::debug!(
        provider = %outcome.provider,
        domain = %outcome.domain,
        status = outcome.status.as_str(),
        degraded = outcome.degraded,
        cached = outcome.cached,
        age_seconds = outcome.age_seconds,
        latency_ms = outcome.latency_ms,
        "provider outcome"
    );
    outcome
}

/// The `_meta` record: who answered, whether an authenticated peer gave a
/// validated answer, how old the facts are, and how the lookup ended.
fn provenance(provider: &RegisteredProvider, outcome: &ProviderOutcome) -> Map<String, Value> {
    // An answer counts as verified only when an authenticated peer gave it; a
    // lookup that failed, including a key the source could never be asked for,
    // has no answer to verify.
    let verified = provider.peer_authenticated
        && !outcome.degraded
        && matches!(
            outcome.status,
            ProviderStatus::Found | ProviderStatus::NoData
        );
    let mut meta = Map::new();
    meta.insert("provider".to_owned(), json!(outcome.provider));
    meta.insert("verified".to_owned(), json!(verified));
    meta.insert("age_seconds".to_owned(), json!(outcome.age_seconds));
    meta.insert("degraded".to_owned(), json!(outcome.degraded));
    meta.insert("status".to_owned(), json!(outcome.status.as_str()));
    meta.insert("cached".to_owned(), json!(outcome.cached));
    if let Some(evidence_ref) = &outcome.evidence_ref {
        meta.insert("evidence_ref".to_owned(), json!(evidence_ref));
    }
    meta
}

fn collect(outcomes: &[Option<ProviderOutcome>]) -> Vec<ProviderOutcome> {
    outcomes.iter().flatten().cloned().collect()
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use apf_policy_eval::{
        CedarEvaluator, PolicyRuleDoc, PolicyRuleRole, RuntimeAttestation, RuntimeIdentity, decide,
        enrich_or_deny,
    };
    use serde_json::json;

    use super::*;
    use crate::pip::grpc::testing::{FakeProvider, TcpServer, UnixServer, current_uid, found};
    use crate::pip::provider::{Attributes, LookupFuture};

    /// Answers with a fixed result after a delay and records each lookup.
    struct FakeTransport {
        result: Mutex<Result<LookupResult, ProviderError>>,
        delay: Duration,
        calls: Mutex<Vec<Lookup>>,
    }

    impl FakeTransport {
        fn new(result: Result<LookupResult, ProviderError>) -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(result),
                delay: Duration::ZERO,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn slow(result: Result<LookupResult, ProviderError>, delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(result),
                delay,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn set(&self, result: Result<LookupResult, ProviderError>) {
            *self.result.lock().expect("lock") = result;
        }

        fn calls(&self) -> Vec<Lookup> {
            self.calls.lock().expect("lock").clone()
        }
    }

    impl ProviderTransport for FakeTransport {
        fn lookup<'a>(&'a self, lookup: Lookup, _budget: Duration) -> LookupFuture<'a> {
            Box::pin(async move {
                self.calls.lock().expect("lock").push(lookup);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                self.result.lock().expect("lock").clone()
            })
        }
    }

    /// Panics inside the lookup task.
    struct PanickingTransport;

    impl ProviderTransport for PanickingTransport {
        fn lookup<'a>(&'a self, _lookup: Lookup, _budget: Duration) -> LookupFuture<'a> {
            Box::pin(async move { panic!("provider transport bug") })
        }
    }

    fn employee(flag: bool) -> Result<LookupResult, ProviderError> {
        let mut claims = Map::new();
        claims.insert("employee".to_owned(), json!(flag));
        claims.insert("groups".to_owned(), json!(["eng"]));
        Ok(LookupResult::Found(Attributes {
            claims,
            ttl_seconds: 60,
            age_seconds: 5,
            evidence_ref: Some("hr-2026".to_owned()),
        }))
    }

    fn registered(
        name: &str,
        domain: &str,
        transport: Arc<dyn ProviderTransport>,
        on_failure: FailureMode,
    ) -> RegisteredProvider {
        RegisteredProvider {
            name: name.to_owned(),
            domain: domain.to_owned(),
            transport,
            peer_authenticated: true,
            budget: Duration::from_millis(200),
            on_failure,
            trigger: Trigger::default(),
            subject: subject::default_subject(),
        }
    }

    fn input() -> EvalInput {
        let mut args = Map::new();
        args.insert("project".to_owned(), json!("nv/apf"));
        args.insert("iid".to_owned(), json!(214));
        let mut input = EvalInput::for_tool_call(
            Some("gitlab".to_owned()),
            Some("merge_request_merge".to_owned()),
            "user@corp.com".to_owned(),
            args,
        );
        input.runtime = Some(RuntimeIdentity {
            platform: "openshell".to_owned(),
            instance_id: "sb-7f2e".to_owned(),
            agent_type: None,
            attestation: RuntimeAttestation::OpenshellSupervisorJwt,
        });
        input
    }

    fn enricher(providers: Vec<RegisteredProvider>) -> ProviderContextEnricher {
        ProviderContextEnricher::new(providers, Duration::from_millis(1000))
    }

    fn limits() -> Limits {
        Limits {
            stage_budget: Duration::from_millis(250),
            gateway_socket: None,
        }
    }

    fn meta(input: &EvalInput, domain: &str) -> Map<String, Value> {
        input.context_attributes[domain]["_meta"]
            .as_object()
            .cloned()
            .expect("_meta record")
    }

    fn cedar(definition: &str) -> CedarEvaluator {
        CedarEvaluator::from_policy_rules(
            &[PolicyRuleDoc {
                name: "grant".to_owned(),
                schema: None,
                definition: definition.to_owned(),
                data: json!({}),
                role: PolicyRuleRole::Grant,
            }],
            &[],
            &[],
            &[],
        )
        .expect("evaluator")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn found_attributes_reach_the_input_with_provenance() {
        let transport = FakeTransport::new(employee(true));
        let stage = enricher(vec![registered(
            "idp",
            "identity",
            transport.clone(),
            FailureMode::FailClosed,
        )]);
        let mut request = input();
        let outcomes = stage
            .enrich(&mut request, Some("req-7"))
            .await
            .expect("enriched");

        let identity = &request.context_attributes["identity"];
        assert_eq!(identity["employee"], json!(true));
        assert_eq!(identity["groups"], json!(["eng"]));
        let meta = meta(&request, "identity");
        assert_eq!(meta["provider"], json!("idp"));
        assert_eq!(meta["verified"], json!(true));
        assert_eq!(meta["age_seconds"], json!(5));
        assert_eq!(meta["degraded"], json!(false));
        assert_eq!(meta["status"], json!("found"));
        assert_eq!(meta["cached"], json!(false));
        assert_eq!(meta["evidence_ref"], json!("hr-2026"));

        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert_eq!(outcome.provider, "idp");
        assert_eq!(outcome.domain, "identity");
        assert_eq!(outcome.status, ProviderStatus::Found);
        assert!(!outcome.degraded);
        assert!(!outcome.cached);
        assert_eq!(outcome.age_seconds, 5);
        assert_eq!(outcome.evidence_ref.as_deref(), Some("hr-2026"));

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].correlation_id, "req-7");
        assert_eq!(calls[0].domain, "identity");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cedar_reads_the_provider_claims_through_decide() {
        let transport = FakeTransport::new(employee(true));
        let stage = enricher(vec![registered(
            "idp",
            "identity",
            transport.clone(),
            FailureMode::FailClosed,
        )]);
        let evaluator = cedar(
            "permit(principal, action, resource) when { context.identity.employee && context.identity._meta.verified };",
        );
        let evaluation = decide(Some(&stage), &evaluator, input(), Some("req-1"))
            .await
            .expect("evaluated");
        assert!(evaluation.result.allow, "{}", evaluation.result.deny_reason);
        assert_eq!(evaluation.providers.len(), 1);
        assert_eq!(evaluation.providers[0].status, ProviderStatus::Found);

        transport.set(employee(false));
        let evaluation = decide(Some(&stage), &evaluator, input(), Some("req-2"))
            .await
            .expect("evaluated");
        assert!(!evaluation.result.allow);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn projection_sends_only_declared_paths() {
        let by_default = FakeTransport::new(employee(true));
        let with_args = FakeTransport::new(employee(true));
        let mut declared = registered("cm", "change", with_args.clone(), FailureMode::Degrade);
        declared.subject = vec![
            SubjectPath::Action,
            SubjectPath::Arg("project".to_owned()),
            SubjectPath::TargetHost,
        ];
        let stage = enricher(vec![
            registered("idp", "identity", by_default.clone(), FailureMode::Degrade),
            declared,
        ]);
        let mut request = input();
        request.target = Some(apf_policy_eval::RequestTarget {
            host: "gitlab.example.com".to_owned(),
            method: "PUT".to_owned(),
            path: "/merge".to_owned(),
            scheme: "https".to_owned(),
        });
        stage
            .enrich(&mut request, Some("req-9"))
            .await
            .expect("enriched");

        let seen = &by_default.calls()[0].subject;
        assert_eq!(seen.user_subject, "user@corp.com");
        assert_eq!(seen.tool, "gitlab");
        assert_eq!(seen.capability, "merge_request_merge");
        assert_eq!(seen.action, "gitlab::merge_request_merge");
        assert_eq!(
            seen.runtime.as_ref().expect("runtime").instance_id,
            "sb-7f2e"
        );
        assert!(seen.args.is_none(), "arguments are opt-in");
        assert!(seen.target.is_none(), "target is opt-in");

        let seen = &with_args.calls()[0].subject;
        assert!(seen.user_subject.is_empty(), "identity not declared");
        assert_eq!(seen.action, "gitlab::merge_request_merge");
        let args = seen.args.as_ref().expect("declared args");
        assert_eq!(args.fields.len(), 1, "only the declared argument");
        assert!(args.fields.contains_key("project"));
        assert_eq!(
            seen.target.as_ref().expect("target").host,
            "gitlab.example.com"
        );
        assert_eq!(with_args.calls()[0].correlation_id, "req-9");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_data_is_stamped_with_only_meta() {
        let transport = FakeTransport::new(Ok(LookupResult::NoData));
        let stage = enricher(vec![registered(
            "idp",
            "identity",
            transport.clone(),
            FailureMode::FailClosed,
        )]);
        for _ in 0..2 {
            let mut request = input();
            let outcomes = stage.enrich(&mut request, None).await.expect("no data");
            assert_eq!(outcomes[0].status, ProviderStatus::NoData);
            assert!(!outcomes[0].cached);
            let meta = meta(&request, "identity");
            assert_eq!(meta["status"], json!("no_data"));
            assert_eq!(meta["verified"], json!(true));
            assert_eq!(meta["degraded"], json!(false));
            assert_eq!(
                request.context_attributes["identity"].len(),
                1,
                "only _meta"
            );
        }
        assert_eq!(transport.calls().len(), 2, "every evaluation asks");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn applies_to_matches_the_tool_name_or_the_action_id() {
        let by_action = FakeTransport::new(employee(true));
        let by_tool = FakeTransport::new(employee(true));
        let mut actions = registered("a", "alpha", by_action.clone(), FailureMode::FailClosed);
        actions.trigger = Trigger::new(vec!["gitlab::merge_request_merge".to_owned()]);
        let mut tools = registered("b", "beta", by_tool.clone(), FailureMode::FailClosed);
        tools.trigger = Trigger::new(vec!["slack".to_owned()]);
        let stage = enricher(vec![actions, tools]);
        let mut request = input();
        let outcomes = stage.enrich(&mut request, None).await.expect("enriched");

        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].status, ProviderStatus::Found);
        assert_eq!(outcomes[1].status, ProviderStatus::NotApplicable);
        assert_eq!(outcomes[1].latency_ms, 0);
        assert!(by_tool.calls().is_empty());
        let meta = meta(&request, "beta");
        assert_eq!(meta["status"], json!("not_applicable"));
        assert_eq!(meta["verified"], json!(false));
        assert_eq!(meta["degraded"], json!(false));
        assert_eq!(request.context_attributes["beta"].len(), 1, "only _meta");

        // An entry equal to the tool name matches even when the action id
        // carries a capability.
        let mut request = input();
        request.tool = Some("slack".to_owned());
        let outcomes = stage.enrich(&mut request, None).await.expect("enriched");
        assert_eq!(outcomes[0].status, ProviderStatus::NotApplicable);
        assert_eq!(outcomes[1].status, ProviderStatus::Found);

        // A skipped provider imposes no transport limits on the request.
        let mut request = input();
        request.tool = Some("other".to_owned());
        let long = "x".repeat(MAX_CORRELATION_ID_BYTES + 1);
        let outcomes = stage
            .enrich(&mut request, Some(&long))
            .await
            .expect("skipped");
        assert!(
            outcomes
                .iter()
                .all(|o| o.status == ProviderStatus::NotApplicable)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn provider_timeout_fails_closed_or_degrades() {
        let slow = FakeTransport::slow(employee(true), Duration::from_secs(5));
        let mut closed = registered("idp", "identity", slow.clone(), FailureMode::FailClosed);
        closed.budget = Duration::from_millis(50);
        let stage = enricher(vec![closed]);
        let mut request = input();
        let denied = enrich_or_deny(Some(&stage), &mut request, None)
            .await
            .expect_err("fails closed");
        assert!(!denied.result.allow);
        assert_eq!(denied.result.deny_reason, "pip_timeout:idp");
        assert_eq!(denied.providers.len(), 1);
        assert_eq!(denied.providers[0].status, ProviderStatus::Timeout);
        assert!(!denied.providers[0].degraded);

        let mut degrade = registered("idp", "identity", slow, FailureMode::Degrade);
        degrade.budget = Duration::from_millis(50);
        let stage = enricher(vec![degrade]);
        let mut request = input();
        let outcomes = stage.enrich(&mut request, None).await.expect("degraded");
        assert_eq!(outcomes[0].status, ProviderStatus::Timeout);
        assert!(outcomes[0].degraded);
        let meta = meta(&request, "identity");
        assert_eq!(meta["degraded"], json!(true));
        assert_eq!(meta["status"], json!("timeout"));
        assert_eq!(meta["verified"], json!(false));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stage_budget_turns_pending_lookups_into_timeouts() {
        let fast = FakeTransport::new(employee(true));
        let slow = FakeTransport::slow(employee(true), Duration::from_secs(5));
        let mut lagging = registered("cm", "change", slow, FailureMode::Degrade);
        lagging.budget = Duration::from_secs(5);
        let stage = ProviderContextEnricher::new(
            vec![
                registered("idp", "identity", fast, FailureMode::FailClosed),
                lagging,
            ],
            Duration::from_millis(100),
        );
        let started = Instant::now();
        let mut request = input();
        let outcomes = stage.enrich(&mut request, None).await.expect("enriched");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].status, ProviderStatus::Found);
        assert_eq!(outcomes[1].status, ProviderStatus::Timeout);
        assert!(outcomes[1].degraded);
        assert_eq!(
            request.context_attributes["identity"]["employee"],
            json!(true)
        );
        assert_eq!(meta(&request, "change")["status"], json!("timeout"));

        // The same expiry denies when the lagging provider fails closed.
        let slow = FakeTransport::slow(employee(true), Duration::from_secs(5));
        let mut lagging = registered("cm", "change", slow, FailureMode::FailClosed);
        lagging.budget = Duration::from_secs(5);
        let stage = ProviderContextEnricher::new(vec![lagging], Duration::from_millis(100));
        let error = stage
            .enrich(&mut input(), None)
            .await
            .expect_err("fails closed");
        assert_eq!(error.deny_reason(), "pip_timeout:cm");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn capacity_and_other_failures_follow_the_failure_mode() {
        for (error, expected) in [
            (ProviderError::Capacity, "pip_capacity:idp"),
            (
                ProviderError::Unavailable("down".to_owned()),
                "pip_unavailable:idp",
            ),
            (
                ProviderError::Unauthorized("peer".to_owned()),
                "pip_unauthorized:idp",
            ),
            (
                ProviderError::Misconfigured("no such method".to_owned()),
                "pip_misconfigured:idp",
            ),
            (
                ProviderError::InvalidOutput("nulls".to_owned()),
                "pip_invalid_output:idp",
            ),
            (
                ProviderError::UnusableKey("key 'sandbox' is absent from the request".to_owned()),
                "pip_no_data:idp",
            ),
        ] {
            let transport = FakeTransport::new(Err(error.clone()));
            let stage = enricher(vec![registered(
                "idp",
                "identity",
                transport,
                FailureMode::FailClosed,
            )]);
            let denied = stage.enrich(&mut input(), None).await.expect_err("closed");
            assert_eq!(denied.deny_reason(), expected);

            let transport = FakeTransport::new(Err(error.clone()));
            let stage = enricher(vec![registered(
                "idp",
                "identity",
                transport,
                FailureMode::Degrade,
            )]);
            let mut request = input();
            let outcomes = stage.enrich(&mut request, None).await.expect("degraded");
            assert_eq!(outcomes[0].status, error.status());
            assert!(outcomes[0].degraded);
            let identity = &request.context_attributes["identity"];
            assert_eq!(identity.len(), 1, "a degraded record holds only _meta");
            let meta = meta(&request, "identity");
            assert_eq!(meta["status"], json!(error.status().as_str()));
            assert_eq!(meta["degraded"], json!(true));
            assert_eq!(meta["verified"], json!(false));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_input_denies_even_under_degrade() {
        let transport = FakeTransport::new(employee(true));
        let stage = enricher(vec![registered(
            "idp",
            "identity",
            transport.clone(),
            FailureMode::Degrade,
        )]);
        let long = "x".repeat(MAX_CORRELATION_ID_BYTES + 1);
        let error = stage
            .enrich(&mut input(), Some(&long))
            .await
            .expect_err("caller fault");
        assert_eq!(error.status, ProviderStatus::InvalidInput);
        assert_eq!(error.deny_reason(), "pip_invalid_input:idp");
        assert!(transport.calls().is_empty(), "nothing was sent");

        let exact = "x".repeat(MAX_CORRELATION_ID_BYTES);
        stage
            .enrich(&mut input(), Some(&exact))
            .await
            .expect("at the limit");

        // An oversized projection is the caller's fault too.
        let mut provider = registered("cm", "change", transport.clone(), FailureMode::Degrade);
        provider.subject = vec![SubjectPath::Arg("blob".to_owned())];
        let stage = enricher(vec![provider]);
        let mut request = input();
        request
            .args
            .insert("blob".to_owned(), json!("y".repeat(MAX_MESSAGE_BYTES + 1)));
        let error = stage
            .enrich(&mut request, None)
            .await
            .expect_err("caller fault");
        assert_eq!(error.deny_reason(), "pip_invalid_input:cm");

        // A provider reporting INVALID_ARGUMENT denies regardless of mode.
        let transport = FakeTransport::new(Err(ProviderError::InvalidInput("bad".to_owned())));
        let stage = enricher(vec![registered(
            "idp",
            "identity",
            transport,
            FailureMode::Degrade,
        )]);
        let error = stage.enrich(&mut input(), None).await.expect_err("denied");
        assert_eq!(error.deny_reason(), "pip_invalid_input:idp");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_panicking_lookup_fails_closed_as_internal() {
        let stage = enricher(vec![
            registered(
                "idp",
                "identity",
                FakeTransport::new(employee(true)),
                FailureMode::Degrade,
            ),
            registered(
                "broken",
                "risk",
                Arc::new(PanickingTransport),
                FailureMode::Degrade,
            ),
        ]);
        let error = stage.enrich(&mut input(), None).await.expect_err("denied");
        assert_eq!(error.provider, "broken");
        assert_eq!(error.status, ProviderStatus::Internal);
        assert_eq!(error.deny_reason(), "pip_internal:broken");
        assert!(error.outcomes.iter().any(|o| o.provider == "broken"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_provider_yields_one_outcome_in_registration_order() {
        let mut skipped = registered(
            "cm",
            "change",
            FakeTransport::new(employee(true)),
            FailureMode::Degrade,
        );
        skipped.trigger = Trigger::new(vec!["other".to_owned()]);
        let stage = enricher(vec![
            skipped,
            registered(
                "idp",
                "identity",
                FakeTransport::new(employee(true)),
                FailureMode::FailClosed,
            ),
            registered(
                "risk",
                "risk",
                FakeTransport::new(Err(ProviderError::Unavailable("down".to_owned()))),
                FailureMode::Degrade,
            ),
        ]);
        let mut request = input();
        let outcomes = stage.enrich(&mut request, None).await.expect("enriched");
        let summary: Vec<(&str, ProviderStatus, bool)> = outcomes
            .iter()
            .map(|o| (o.provider.as_str(), o.status, o.degraded))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("cm", ProviderStatus::NotApplicable, false),
                ("idp", ProviderStatus::Found, false),
                ("risk", ProviderStatus::Unavailable, true),
            ]
        );
        assert_eq!(request.context_attributes.len(), 3);
        let fail_closed_outcomes = enrich_or_deny(Some(&stage), &mut input(), None)
            .await
            .expect("degrade keeps the evaluation going");
        assert_eq!(fail_closed_outcomes.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_registry_is_a_no_op() {
        let stage = enricher(Vec::new());
        assert!(stage.is_empty());
        assert_eq!(stage.contexts().count(), 0);
        let mut request = input();
        let outcomes = stage
            .enrich(&mut request, None)
            .await
            .expect("nothing to do");
        assert!(outcomes.is_empty());
        assert!(request.context_attributes.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn grpc_provider_over_a_unix_socket_reaches_cedar() {
        let server = UnixServer::start(FakeProvider::new(found(
            json!({"identity": {"employee": true}}),
            30,
        )));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        let stage = enricher(vec![registered(
            "idp",
            "identity",
            Arc::new(transport),
            FailureMode::FailClosed,
        )]);
        let evaluator =
            cedar("permit(principal, action, resource) when { context.identity.employee };");
        let evaluation = decide(Some(&stage), &evaluator, input(), Some("req-1"))
            .await
            .expect("evaluated");
        assert!(evaluation.result.allow, "{}", evaluation.result.deny_reason);
        assert_eq!(evaluation.providers[0].status, ProviderStatus::Found);
        assert_eq!(
            evaluation.providers[0].evidence_ref.as_deref(),
            Some("obs-1")
        );

        let requests = server.fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].correlation_id, "req-1");
        assert_eq!(requests[0].domains, ["identity"]);
        let subject = requests[0].subject.as_ref().expect("subject");
        assert_eq!(subject.action, "gitlab::merge_request_merge");
        assert!(subject.args.is_none());

        server
            .fake
            .reply(Ok(found(json!({"identity": {"employee": false}}), 30)));
        let evaluation = decide(Some(&stage), &evaluator, input(), Some("req-2"))
            .await
            .expect("evaluated");
        assert!(!evaluation.result.allow);

        // Output that fails validation is invalid_output and fails closed.
        server.fake.reply(Ok(found(
            json!({"identity": {"_meta": {"verified": true}}}),
            30,
        )));
        let evaluation = decide(Some(&stage), &evaluator, input(), None)
            .await
            .expect("evaluated");
        assert!(!evaluation.result.allow);
        assert_eq!(evaluation.result.deny_reason, "pip_invalid_output:idp");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn from_config_binds_unix_and_loopback_providers() {
        let unix = UnixServer::start(FakeProvider::new(found(
            json!({"identity": {"employee": true}}),
            30,
        )));
        let tcp = TcpServer::start(FakeProvider::new(found(
            json!({"change": {"approval": "approved"}}),
            0,
        )))
        .await;
        let yaml = format!(
            "providers:\n  - name: identity\n    context: identity\n    type: grpc\n    endpoint:\n      url: unix://{}\n      peer_uid: {}\n    on_failure: fail_closed\n  - name: change-management\n    context: change\n    type: grpc\n    applies_to: [gitlab]\n    endpoint:\n      url: {}\n    on_failure: degrade\n    timeout_ms: 200\n",
            unix.path.display(),
            current_uid(),
            tcp.url
        );
        let config = RegistryConfig::from_yaml(yaml.as_bytes()).expect("yaml");
        let stage = ProviderContextEnricher::from_config(&config, &limits()).expect("enricher");
        assert!(!stage.is_empty());
        assert_eq!(stage.contexts().collect::<Vec<_>>(), ["identity", "change"]);
        assert_eq!(stage.stage_budget(), Duration::from_millis(250));
        assert_eq!(
            stage.providers[0].budget,
            Duration::from_millis(250),
            "an absent timeout is the stage cap"
        );
        assert_eq!(stage.providers[1].budget, Duration::from_millis(200));
        assert_eq!(stage.providers[0].trigger, Trigger::default());
        assert_eq!(
            stage.providers[1].trigger,
            Trigger::new(vec!["gitlab".to_owned()])
        );

        let mut request = input();
        let outcomes = stage
            .enrich(&mut request, Some("req-1"))
            .await
            .expect("enriched");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.status == ProviderStatus::Found));
        assert_eq!(
            request.context_attributes["identity"]["employee"],
            json!(true)
        );
        assert_eq!(
            request.context_attributes["change"]["approval"],
            json!("approved")
        );
        let change_subject = tcp.fake.requests()[0].subject.clone().expect("subject");
        assert_eq!(
            change_subject.user_subject, "user@corp.com",
            "contract providers receive identity and action"
        );
        assert!(change_subject.args.is_none(), "never arguments");

        // A socket the gateway cannot trust fails construction.
        let foreign = yaml.replace(&format!("peer_uid: {}", current_uid()), "peer_uid: 4242");
        let config = RegistryConfig::from_yaml(foreign.as_bytes()).expect("yaml");
        let error = ProviderContextEnricher::from_config(&config, &limits()).expect_err("rejected");
        assert!(
            matches!(error, ConfigError::Provider { ref provider, .. } if provider == "identity"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verified_requires_an_authenticated_peer() {
        let mut plain = registered(
            "idp",
            "identity",
            FakeTransport::new(employee(true)),
            FailureMode::FailClosed,
        );
        plain.peer_authenticated = false;
        let stage = enricher(vec![
            plain,
            registered(
                "cm",
                "change",
                FakeTransport::new(Ok(LookupResult::NoData)),
                FailureMode::FailClosed,
            ),
        ]);
        let mut request = input();
        let outcomes = stage.enrich(&mut request, None).await.expect("enriched");
        assert_eq!(outcomes[0].status, ProviderStatus::Found);
        assert_eq!(outcomes[1].status, ProviderStatus::NoData);
        assert_eq!(
            request.context_attributes["identity"]["employee"],
            json!(true),
            "claims from an unauthenticated peer still land"
        );
        assert_eq!(meta(&request, "identity")["verified"], json!(false));
        assert_eq!(meta(&request, "change")["verified"], json!(true));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn from_config_marks_peer_authentication_by_transport() {
        let unix = UnixServer::start(FakeProvider::new(found(
            json!({"identity": {"employee": true}}),
            30,
        )));
        let tcp = TcpServer::start(FakeProvider::new(found(
            json!({"change": {"approval": "approved"}}),
            0,
        )))
        .await;
        let rest = |name: &str, context: &str, origin: &str| {
            format!(
                "  - name: {name}\n    context: {context}\n    type: http\n    applies_to: [never]\n    endpoint:\n      url: {origin}/api/{{kind}}\n    request:\n      keys:\n        kind: {{ from: tool, pattern: '^[a-z]+$' }}\n    response:\n      keep: [state]\n    on_failure: degrade\n    timeout_ms: 200\n"
            )
        };
        let yaml = format!(
            "providers:\n  - name: identity\n    context: identity\n    type: grpc\n    endpoint:\n      url: unix://{}\n      peer_uid: {}\n    on_failure: fail_closed\n    timeout_ms: 200\n  - name: change-management\n    context: change\n    type: grpc\n    endpoint:\n      url: {}\n    on_failure: fail_closed\n    timeout_ms: 200\n{}{}",
            unix.path.display(),
            current_uid(),
            tcp.url,
            rest("ticket-table", "ticket", "http://127.0.0.1:9"),
            rest("risk-table", "risk", "https://risk.example.com"),
        );
        let config = RegistryConfig::from_yaml(yaml.as_bytes()).expect("yaml");
        let stage = ProviderContextEnricher::from_config(&config, &limits()).expect("enricher");
        let flags: Vec<(&str, bool)> = stage
            .providers
            .iter()
            .map(|provider| (provider.name.as_str(), provider.peer_authenticated))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("identity", true),
                ("change-management", false),
                ("ticket-table", false),
                ("risk-table", false),
            ]
        );
        assert_eq!(
            stage.providers[2].subject,
            vec![SubjectPath::Tool],
            "a REST provider receives only its key sources"
        );
        assert_eq!(stage.providers[0].subject, subject::default_subject());

        let mut request = input();
        let outcomes = stage
            .enrich(&mut request, Some("req-1"))
            .await
            .expect("enriched");
        assert_eq!(outcomes[0].status, ProviderStatus::Found);
        assert_eq!(outcomes[1].status, ProviderStatus::Found);
        assert_eq!(outcomes[2].status, ProviderStatus::NotApplicable);
        assert_eq!(outcomes[3].status, ProviderStatus::NotApplicable);
        assert_eq!(meta(&request, "identity")["verified"], json!(true));
        assert_eq!(meta(&request, "change")["verified"], json!(false));
        assert_eq!(
            request.context_attributes["change"]["approval"],
            json!("approved"),
            "claims from the loopback provider still land"
        );
    }
}
