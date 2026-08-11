// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use apf_policy_eval::{
    CedarEvaluator, EvalError, Evaluator, PolicyAnnotatorDoc, PolicyEffectDoc, PolicyFindingDoc,
    PolicyRuleDoc,
};

pub fn build_evaluator(
    policy_rules: &[PolicyRuleDoc],
    policy_annotators: &[PolicyAnnotatorDoc],
    policy_effects: &[PolicyEffectDoc],
    policy_findings: &[PolicyFindingDoc],
) -> Result<Arc<dyn Evaluator>, EvalError> {
    Ok(Arc::new(CedarEvaluator::from_policy_rules(
        policy_rules,
        policy_annotators,
        policy_effects,
        policy_findings,
    )?))
}

/// Shared read handle for the current evaluator.
///
/// Receivers clone the inner `Arc<dyn Evaluator>` on each call; the sender
/// atomically swaps the value when a bundle refresh completes.
///
/// Note: `arc-swap 1.x` requires `T: Sized` so `ArcSwap<Arc<dyn Evaluator>>` is
/// unavailable. `tokio::sync::watch` provides equivalent semantics (cheap
/// broadcast, no per-read lock on the hot path).
pub type EvaluatorReceiver = tokio::sync::watch::Receiver<Arc<dyn Evaluator>>;
pub type EvaluatorSender = tokio::sync::watch::Sender<Arc<dyn Evaluator>>;

/// Create a sender/receiver pair initialised with `evaluator`.
pub fn new_evaluator_channel(
    evaluator: Arc<dyn Evaluator>,
) -> (EvaluatorSender, EvaluatorReceiver) {
    tokio::sync::watch::channel(evaluator)
}
