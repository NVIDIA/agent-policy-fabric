// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use apf_policy_eval::{
    ActivePolicy, CedarEvaluator, EvalError, Evaluator, PolicyAnnotatorDoc, PolicyEffectDoc,
    PolicyFindingDoc, PolicyRuleDoc,
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

/// Shared read handle for the current policy.
///
/// Receivers clone the inner `Arc<ActivePolicy>` on each call; the sender
/// atomically swaps the value when a bundle refresh completes.
///
/// `watch` rather than `ArcSwap`: receivers can also await a change, which the
/// refresh path needs.
pub type EvaluatorReceiver = tokio::sync::watch::Receiver<Arc<ActivePolicy>>;
pub type EvaluatorSender = tokio::sync::watch::Sender<Arc<ActivePolicy>>;

/// Create a sender/receiver pair initialised with `policy`.
pub fn new_evaluator_channel(policy: ActivePolicy) -> (EvaluatorSender, EvaluatorReceiver) {
    tokio::sync::watch::channel(Arc::new(policy))
}
