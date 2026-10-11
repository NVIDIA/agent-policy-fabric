// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The enrichment stage of the decision pipeline.
//!
//! Enrichment runs before the policy engine. A [`ContextEnricher`] consults
//! the registered policy information providers and writes their attributes
//! into [`EvalInput::context_attributes`], one record per namespace, with the
//! provenance record the gateway stamps as `_meta`. The engine then evaluates
//! the enriched input; each engine adapter maps the namespaces into its own
//! input shape, so the stage itself knows nothing about any policy language.
//!
//! [`enrich_or_deny`] applies the one failure rule shared by every
//! enforcement surface: a provider registered to fail closed that cannot
//! answer denies the request before the engine runs. [`decide`] composes that
//! with the engine for callers that evaluate on the same task.

use std::future::Future;
use std::pin::Pin;

use crate::{EvalError, EvalInput, EvalResult, Evaluator};

/// Future returned by [`ContextEnricher::enrich`].
pub type EnrichFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<ProviderOutcome>, EnrichmentError>> + Send + 'a>>;

/// Supplies trusted context attributes for one evaluation.
pub trait ContextEnricher: Send + Sync {
    /// Populate `input.context_attributes` from the registered providers and
    /// report what each provider contributed. The correlation id is forwarded
    /// to providers for audit joins and is never a cache key. An error means a
    /// fail-closed provider could not answer.
    fn enrich<'a>(
        &'a self,
        input: &'a mut EvalInput,
        correlation_id: Option<&'a str>,
    ) -> EnrichFuture<'a>;
}

/// What one provider contributed to an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderOutcome {
    /// Registered provider name.
    pub provider: String,
    /// Namespace domain the provider owns, e.g. `identity`.
    pub domain: String,
    pub status: ProviderStatus,
    /// `true` when the provider failed and its failure mode let the
    /// evaluation continue without its attributes.
    pub degraded: bool,
    /// `true` when the attributes came from the enrichment cache.
    pub cached: bool,
    /// Age of the attributes in seconds: the provider's reported fact age
    /// plus the time they spent in the enrichment cache.
    pub age_seconds: u64,
    /// Provider-supplied pointer to the evidence behind the attributes.
    pub evidence_ref: Option<String>,
    /// Wall-clock time the lookup took, zero for cache hits and skipped
    /// providers.
    pub latency_ms: u64,
}

/// Outcome of one provider lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatus {
    /// Attributes were supplied.
    Found,
    /// The lookup succeeded and the provider holds nothing for the subject.
    NoData,
    /// The provider's trigger did not match the request; no lookup was made.
    NotApplicable,
    /// The provider did not answer within its budget.
    Timeout,
    /// The provider could not be reached.
    Unavailable,
    /// The provider's in-flight limit was reached.
    Capacity,
    /// The provider answered with output that failed validation.
    InvalidOutput,
    /// The evaluation input could not be sent to the provider.
    InvalidInput,
    /// The provider refused the gateway's identity.
    Unauthorized,
    /// The provider or its source is misconfigured, for example a rejected
    /// credential or an unimplemented method.
    Misconfigured,
    /// The enrichment stage itself failed.
    Internal,
}

impl ProviderStatus {
    /// Stable lower-case name used in provenance and deny reasons.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::NoData => "no_data",
            Self::NotApplicable => "not_applicable",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Capacity => "capacity",
            Self::InvalidOutput => "invalid_output",
            Self::InvalidInput => "invalid_input",
            Self::Unauthorized => "unauthorized",
            Self::Misconfigured => "misconfigured",
            Self::Internal => "internal",
        }
    }

    /// Whether the provider failed to supply an answer.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Found | Self::NoData | Self::NotApplicable)
    }

    /// Whether the failure is attributable to the caller's request rather
    /// than the provider. Such failures deny regardless of the provider's
    /// failure mode, so a caller cannot induce degradation.
    #[must_use]
    pub const fn is_caller_fault(self) -> bool {
        matches!(self, Self::InvalidInput)
    }
}

/// A provider could not answer and the evaluation must not continue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("provider '{provider}' failed closed: {}", status.as_str())]
pub struct EnrichmentError {
    pub provider: String,
    pub status: ProviderStatus,
    /// Outcomes gathered before the failure, for the audit record.
    pub outcomes: Vec<ProviderOutcome>,
}

impl EnrichmentError {
    /// Deny reason naming the failure and the provider.
    #[must_use]
    pub fn deny_reason(&self) -> String {
        format!("pip_{}:{}", self.status.as_str(), self.provider)
    }
}

/// An evaluation together with the provider contributions behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub result: EvalResult,
    pub providers: Vec<ProviderOutcome>,
}

/// Run the enrichment stage, or produce the deny it mandates.
///
/// Caller-supplied attributes are discarded first: only the enrichment stage
/// may write them. With no enricher the input is left as it is. A fail-closed
/// failure yields a denied [`Evaluation`] with [`EnrichmentError::deny_reason`]
/// so the caller skips the engine and records the outcomes gathered so far.
///
/// # Errors
///
/// The error variant carries the deny the caller must return.
pub async fn enrich_or_deny(
    enricher: Option<&dyn ContextEnricher>,
    input: &mut EvalInput,
    correlation_id: Option<&str>,
) -> Result<Vec<ProviderOutcome>, Evaluation> {
    input.context_attributes.clear();
    let Some(enricher) = enricher else {
        return Ok(Vec::new());
    };
    enricher
        .enrich(input, correlation_id)
        .await
        .map_err(|error| Evaluation {
            result: EvalResult {
                allow: false,
                deny_reason: error.deny_reason(),
                ..EvalResult::default()
            },
            providers: error.outcomes,
        })
}

/// Enrich the input, then evaluate it on the current task.
///
/// # Errors
///
/// Returns the engine's error when evaluation itself fails.
pub async fn decide(
    enricher: Option<&dyn ContextEnricher>,
    evaluator: &dyn Evaluator,
    mut input: EvalInput,
    correlation_id: Option<&str>,
) -> Result<Evaluation, EvalError> {
    let providers = match enrich_or_deny(enricher, &mut input, correlation_id).await {
        Ok(providers) => providers,
        Err(denied) => return Ok(denied),
    };
    let result = evaluator.evaluate(input)?;
    Ok(Evaluation { result, providers })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;

    /// Records the input it saw and allows.
    struct RecordingEvaluator(Mutex<Option<EvalInput>>);

    impl Evaluator for RecordingEvaluator {
        fn evaluate(&self, input: EvalInput) -> Result<EvalResult, EvalError> {
            *self.0.lock().expect("lock") = Some(input);
            Ok(EvalResult::default())
        }
    }

    /// Writes one namespace, records the correlation id it was given, and
    /// reports the lookup as found.
    struct StaticEnricher(Mutex<Option<String>>);

    impl ContextEnricher for StaticEnricher {
        fn enrich<'a>(
            &'a self,
            input: &'a mut EvalInput,
            correlation_id: Option<&'a str>,
        ) -> EnrichFuture<'a> {
            Box::pin(async move {
                *self.0.lock().expect("lock") = correlation_id.map(str::to_owned);
                let record = json!({
                    "approval": "approved",
                    "_meta": {"provider": "cm", "verified": true}
                });
                input.context_attributes.insert(
                    "change".to_string(),
                    record.as_object().cloned().expect("record"),
                );
                Ok(vec![ProviderOutcome {
                    provider: "cm".to_string(),
                    domain: "change".to_string(),
                    status: ProviderStatus::Found,
                    degraded: false,
                    cached: false,
                    age_seconds: 0,
                    evidence_ref: Some("CHG0012".to_string()),
                    latency_ms: 3,
                }])
            })
        }
    }

    struct FailingEnricher;

    impl ContextEnricher for FailingEnricher {
        fn enrich<'a>(
            &'a self,
            _input: &'a mut EvalInput,
            _correlation_id: Option<&'a str>,
        ) -> EnrichFuture<'a> {
            Box::pin(async move {
                Err(EnrichmentError {
                    provider: "cm".to_string(),
                    status: ProviderStatus::Timeout,
                    outcomes: vec![ProviderOutcome {
                        provider: "idp".to_string(),
                        domain: "identity".to_string(),
                        status: ProviderStatus::Found,
                        degraded: false,
                        cached: true,
                        age_seconds: 12,
                        evidence_ref: None,
                        latency_ms: 0,
                    }],
                })
            })
        }
    }

    fn input() -> EvalInput {
        EvalInput::for_tool_call(
            Some("gitlab".to_string()),
            Some("merge_request_merge".to_string()),
            "user@corp.com".to_string(),
            serde_json::Map::new(),
        )
    }

    #[tokio::test]
    async fn enriched_attributes_reach_the_evaluator() {
        let evaluator = RecordingEvaluator(Mutex::new(None));
        let enricher = StaticEnricher(Mutex::new(None));
        let evaluation = decide(Some(&enricher), &evaluator, input(), Some("req-7"))
            .await
            .unwrap();
        assert!(evaluation.result.allow);
        assert_eq!(evaluation.providers.len(), 1);
        assert_eq!(evaluation.providers[0].status, ProviderStatus::Found);
        assert_eq!(enricher.0.lock().unwrap().as_deref(), Some("req-7"));
        let seen = evaluator.0.lock().unwrap().clone().expect("evaluated");
        assert_eq!(
            seen.context_attributes["change"]["approval"],
            json!("approved")
        );
    }

    #[tokio::test]
    async fn caller_supplied_attributes_are_discarded() {
        let evaluator = RecordingEvaluator(Mutex::new(None));
        let mut forged = input();
        forged.context_attributes.insert(
            "identity".to_string(),
            json!({"admin": true}).as_object().cloned().unwrap(),
        );
        decide(None, &evaluator, forged, None).await.unwrap();
        let seen = evaluator.0.lock().unwrap().clone().expect("evaluated");
        assert!(seen.context_attributes.is_empty());
    }

    #[tokio::test]
    async fn fail_closed_provider_denies_before_the_engine_runs() {
        let evaluator = RecordingEvaluator(Mutex::new(None));
        let evaluation = decide(Some(&FailingEnricher), &evaluator, input(), None)
            .await
            .unwrap();
        assert!(!evaluation.result.allow);
        assert_eq!(evaluation.result.deny_reason, "pip_timeout:cm");
        assert_eq!(evaluation.providers.len(), 1, "earlier outcomes are kept");
        assert!(
            evaluator.0.lock().unwrap().is_none(),
            "the engine must not see a request a fail-closed provider blocked"
        );
    }

    #[tokio::test]
    async fn enrich_or_deny_hands_the_deny_to_the_caller() {
        let mut request = input();
        let denied = enrich_or_deny(Some(&FailingEnricher), &mut request, None)
            .await
            .expect_err("a fail-closed failure is a deny");
        assert!(!denied.result.allow);
        assert_eq!(denied.result.deny_reason, "pip_timeout:cm");

        let mut request = input();
        let providers = enrich_or_deny(None, &mut request, None)
            .await
            .expect("no enricher is a no-op");
        assert!(providers.is_empty());
    }

    #[test]
    fn status_names_are_stable() {
        assert_eq!(ProviderStatus::NoData.as_str(), "no_data");
        assert_eq!(ProviderStatus::InvalidOutput.as_str(), "invalid_output");
        assert_eq!(ProviderStatus::Misconfigured.as_str(), "misconfigured");
        assert!(ProviderStatus::Timeout.is_failure());
        assert!(!ProviderStatus::NotApplicable.is_failure());
        assert!(ProviderStatus::InvalidInput.is_caller_fault());
        assert!(!ProviderStatus::Unavailable.is_caller_fault());
    }
}
