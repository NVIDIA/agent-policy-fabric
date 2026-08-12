// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use apf_policy_eval::EvalInput;
use apf_proto::pdp_v1alpha1::{
    Decision, EvaluateRequest, EvaluateResponse, evaluation_service_server::EvaluationService,
};

use crate::engine::EvaluatorReceiver;

pub struct EvaluationServiceImpl {
    pub evaluator: EvaluatorReceiver,
}

#[tonic::async_trait]
impl EvaluationService for EvaluationServiceImpl {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let req = request.into_inner();
        // Clone the current evaluator Arc — cheap, lock-free on the hot path.
        let evaluator = self.evaluator.borrow().clone();

        // Extract subject from RuntimeContext.
        let user_subject = req
            .context
            .as_ref()
            .and_then(|c| c.platform.as_ref())
            .map(|p| match p {
                apf_proto::runtime_v1alpha1::runtime_context::Platform::Openshell(o) => {
                    o.user_subject.clone()
                }
            })
            .unwrap_or_default();

        let args: serde_json::Map<String, serde_json::Value> = req
            .args
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();

        let input = EvalInput::for_tool_call(
            req.resource.as_ref().map(|r| r.class.clone()),
            Some(req.verb.clone()),
            user_subject,
            args,
        );

        let result = evaluator
            .evaluate(input)
            .map_err(|e| Status::internal(e.to_string()))?;

        let decision = if result.allow {
            Decision::Allow
        } else {
            Decision::Deny
        };

        Ok(Response::new(EvaluateResponse {
            decision: decision as i32,
            obligations: vec![],
            policy_digest_hex: String::new(),
            reason: result.deny_reason,
            rejection_reasons: vec![],
        }))
    }
}
