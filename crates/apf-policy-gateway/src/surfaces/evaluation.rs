// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use apf_policy_eval::EvalInput;
use apf_proto::pdp_v1alpha1::{
    Decision, EvaluateRequest, EvaluateResponse, evaluation_service_server::EvaluationService,
};

use crate::audit::{DecisionRecord, PolicyGatewayAudit, findings_for_audit, verdict_for_audit};
use crate::engine::EvaluatorReceiver;

pub struct EvaluationServiceImpl {
    pub evaluator: EvaluatorReceiver,
    pub audit: PolicyGatewayAudit,
}

#[tonic::async_trait]
impl EvaluationService for EvaluationServiceImpl {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let req = request.into_inner();
        // One read: the evaluator and the digest of the bundle it came from
        // travel together, so a hot-swap cannot pair a decision with another
        // bundle's identity.
        let active = self.evaluator.borrow().clone();

        // Extract subject from RuntimeContext.
        let openshell = req
            .context
            .as_ref()
            .and_then(|c| c.platform.as_ref())
            .map(|p| match p {
                apf_proto::runtime_v1alpha1::runtime_context::Platform::Openshell(o) => o,
            });
        let user_subject = openshell
            .map(|o| o.user_subject.clone())
            .unwrap_or_default();
        // Well-known key, so a decision joins to the calling gateway's events.
        let caller_correlation_id = req
            .context
            .as_ref()
            .and_then(|c| c.audit_context.get("correlation_id"))
            .map(String::as_str);

        let args: serde_json::Map<String, serde_json::Value> = req
            .args
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();

        // Cloned before `user_subject` is moved into the evaluator input.
        let subject_for_audit = user_subject.clone();

        let input = EvalInput::for_tool_call(
            req.resource.as_ref().map(|r| r.class.clone()),
            Some(req.verb.clone()),
            user_subject,
            args,
        );

        let result = active
            .evaluator
            .evaluate(input)
            .map_err(|e| Status::internal(e.to_string()))?;

        let decision = if result.allow {
            Decision::Allow
        } else {
            Decision::Deny
        };

        // After the decision, so the record never describes one still in doubt.
        // Best-effort: a full disk must not take enforcement down.
        if let Err(e) = self.audit.emit_decision(&DecisionRecord {
            allow: result.allow,
            resource_class: req.resource.as_ref().map_or("", |r| r.class.as_str()),
            resource_id: req.resource.as_ref().map_or("", |r| r.id.as_str()),
            verb: &req.verb,
            subject: &subject_for_audit,
            agent_type: openshell.map_or("", |o| o.agent_type.as_str()),
            sandbox_id: openshell.map_or("", |o| o.sandbox_id.as_str()),
            correlation_id: caller_correlation_id,
            deny_reason: &result.deny_reason,
            verdict: verdict_for_audit(result.verdict),
            findings: &findings_for_audit(&result.findings),
            // Both read from the same `active`, never re-read: a hot-swap
            // between two reads would name a policy other than the one that
            // decided.
            bundle_digest: &active.bundle_digest,
            policy_revision: active.policy_revision,
        }) {
            tracing::warn!(error = %e, "audit emission failed for evaluation decision");
        }

        Ok(Response::new(EvaluateResponse {
            decision: decision as i32,
            obligations: vec![],
            policy_digest_hex: active.bundle_digest.clone(),
            reason: result.deny_reason,
            rejection_reasons: vec![],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Seam;
    use crate::engine::new_evaluator_channel;
    use apf_audit::AuditEvent;
    use apf_policy_eval::{
        ActivePolicy, EvalError, EvalResult, Evaluator, Finding, Severity, Verdict,
    };
    use apf_proto::pdp_v1alpha1::Resource as ResourceRef;
    use apf_proto::runtime_v1alpha1::{OpenShellContext, runtime_context};
    use std::sync::Arc;

    /// Returns a fixed result, so a test pins what the handler records rather
    /// than what Cedar decides.
    struct FixedEvaluator(EvalResult);

    impl Evaluator for FixedEvaluator {
        fn evaluate(&self, _: apf_policy_eval::EvalInput) -> Result<EvalResult, EvalError> {
            Ok(self.0.clone())
        }
    }

    const DIGEST: &str = "a1b2c3";
    const REVISION: u64 = 42;

    fn service(result: EvalResult, dir: &std::path::Path) -> EvaluationServiceImpl {
        let (_tx, rx) = new_evaluator_channel(ActivePolicy {
            evaluator: Arc::new(FixedEvaluator(result)),
            bundle_digest: DIGEST.to_owned(),
            policy_revision: REVISION,
        });
        // `borrow()` still returns the current value after the sender drops —
        // only `changed()` would error, and the handler never calls it.
        drop(_tx);
        EvaluationServiceImpl {
            evaluator: rx,
            audit: PolicyGatewayAudit::to_jsonl_in(dir, Seam::Pdp).expect("build emitter"),
        }
    }

    fn records(dir: &std::path::Path) -> Vec<AuditEvent> {
        let written = std::fs::read_to_string(dir.join("apf-policy-gateway-audit.jsonl"))
            .expect("audit log was written");
        written
            .lines()
            .map(|line| {
                let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
                parsed.validate().expect("validates against the schema");
                parsed
            })
            .collect()
    }

    fn request() -> Request<EvaluateRequest> {
        request_from("alice@corp")
    }

    fn request_with_correlation(correlation_id: &str) -> Request<EvaluateRequest> {
        let mut req = request();
        let inner = req.get_mut();
        if let Some(ctx) = inner.context.as_mut() {
            ctx.audit_context
                .insert("correlation_id".to_owned(), correlation_id.to_owned());
        }
        req
    }

    fn request_from(subject: &str) -> Request<EvaluateRequest> {
        Request::new(EvaluateRequest {
            resource: Some(ResourceRef {
                class: "network.egress".to_owned(),
                id: "mailbox-ceo".to_owned(),
                ..Default::default()
            }),
            verb: "http.post".to_owned(),
            context: Some(apf_proto::runtime_v1alpha1::RuntimeContext {
                platform: Some(runtime_context::Platform::Openshell(OpenShellContext {
                    user_subject: subject.to_owned(),
                    sandbox_id: "sbx-9".to_owned(),
                    agent_type: "claude-code".to_owned(),
                })),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// An allowed request must leave a record naming the policy that allowed
    /// it. Asserted through the handler, not the emitter: the emitter cannot
    /// see which decision was reached, so only a call-site test catches an
    /// allow recorded as a deny.
    #[tokio::test]
    async fn an_allowed_request_is_recorded_against_the_deciding_policy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(EvalResult::default(), dir.path());

        svc.evaluate(request()).await.expect("allow");

        let records = records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(r.decision, Some(apf_audit::Decision::Allow));
        assert_eq!(r.verb.as_deref(), Some("http.post"));
        assert_eq!(
            r.bundle_digest.as_deref(),
            Some(DIGEST),
            "the record must name the policy that decided"
        );
        assert_eq!(r.policy_revision, Some(REVISION));

        // The subject is who acted; the resource is what was acted on.
        // Recording the caller as the resource makes "who was denied"
        // unanswerable and "what was touched" return a person.
        let resource = r.resource.as_ref().expect("resource recorded");
        assert_eq!(resource.resource_type, "network.egress");
        assert_eq!(resource.id, "mailbox-ceo");
        assert_eq!(r.user_id.as_deref(), Some("alice@corp"));
        assert_eq!(r.agent_id.as_deref(), Some("claude-code"));
        assert_eq!(r.session_id.as_deref(), Some("sbx-9"));
    }

    /// A caller who cannot erase their record must not be able to invert it
    /// either. A credential-shaped subject trips the sanitizer and forces the
    /// fallback, which must still record an allow as an allow.
    #[tokio::test]
    async fn a_sanitizer_trip_cannot_invert_an_allow_into_a_denial() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(EvalResult::default(), dir.path());

        svc.evaluate(request_from("AKIAAAAAAAAAAAAAAAAA"))
            .await
            .expect("allow");

        let records = records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(
            r.decision,
            Some(apf_audit::Decision::Allow),
            "an allowed request must never be recorded as denied"
        );
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied request detail omitted"),
            "the record must say it was degraded"
        );
    }

    /// The mirror of the allow case: the fallback's decision is a runtime
    /// value now, so only this pins that a degraded denial stays a denial.
    #[tokio::test]
    async fn a_sanitizer_trip_cannot_soften_a_denial_into_an_allow() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(
            EvalResult {
                allow: false,
                deny_reason: "no grant".to_owned(),
                ..Default::default()
            },
            dir.path(),
        );

        svc.evaluate(request_from("AKIAAAAAAAAAAAAAAAAA"))
            .await
            .expect("deny is still a normal response");

        let records = records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(
            r.decision,
            Some(apf_audit::Decision::Deny),
            "a denied request must never be recorded as allowed"
        );
        assert_eq!(
            r.reason_code.as_deref(),
            Some("policy.request_denied"),
            "the decision and its reason code travel together"
        );
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied request detail omitted"),
            "the record must say it was degraded"
        );
    }

    /// The correlation id is caller-supplied and lands in `common`, which the
    /// fallback reuses — so a value that trips the sanitizer would fail both
    /// attempts and erase the record rather than degrade it.
    #[tokio::test]
    async fn a_hostile_correlation_id_cannot_erase_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(EvalResult::default(), dir.path());

        svc.evaluate(request_with_correlation("AKIAAAAAAAAAAAAAAAAA"))
            .await
            .expect("allow");

        let records = records(dir.path());
        assert_eq!(records.len(), 1, "the request must still leave a record");
        assert_eq!(records[0].decision, Some(apf_audit::Decision::Allow));
    }

    /// The schema caps findings at 32. Over that the record would degrade to a
    /// bare fallback, losing everything — on the requests with the most
    /// detections, which are the ones worth having.
    #[tokio::test]
    async fn a_flood_of_findings_does_not_cost_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(
            EvalResult {
                allow: false,
                findings: (0..64)
                    .map(|i| Finding {
                        kind: "content.class".to_owned(),
                        label: format!("label-{i}"),
                        severity: Severity::Low,
                        confidence: None,
                    })
                    .collect(),
                ..Default::default()
            },
            dir.path(),
        );

        svc.evaluate(request()).await.expect("deny is a response");

        let records = records(dir.path());
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].reason, None,
            "the record must carry its detail, not degrade to the fallback"
        );
        assert_eq!(
            records[0]
                .findings
                .as_ref()
                .expect("findings carried")
                .len(),
            32
        );
    }

    /// The cap keeps the most severe, not the first. A lone critical behind a
    /// run of low ones is exactly the finding worth keeping.
    #[tokio::test]
    async fn truncation_keeps_the_most_severe_findings() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut findings: Vec<Finding> = (0..40)
            .map(|i| Finding {
                kind: "content.class".to_owned(),
                label: format!("low-{i}"),
                severity: Severity::Low,
                confidence: None,
            })
            .collect();
        findings.push(Finding {
            kind: "secret_detected".to_owned(),
            label: "the-critical-one".to_owned(),
            severity: Severity::Critical,
            confidence: None,
        });
        let svc = service(
            EvalResult {
                allow: false,
                findings,
                ..Default::default()
            },
            dir.path(),
        );

        svc.evaluate(request()).await.expect("deny is a response");

        let records = records(dir.path());
        let kept = records[0].findings.as_ref().expect("findings carried");
        assert_eq!(kept.len(), 32);
        assert!(
            kept.iter().any(|f| f.label == "the-critical-one"),
            "the critical finding must survive truncation"
        );
    }

    /// A subject that coerces away is recorded as the sentinel, not as absent.
    /// Absence is indistinguishable from an anonymous request and would be
    /// caller-selectable; the sentinel is forgeable but visible.
    #[tokio::test]
    async fn an_unrecordable_subject_is_recorded_as_the_sentinel() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(EvalResult::default(), dir.path());

        svc.evaluate(request_from("!!!")).await.expect("allow");

        let records = records(dir.path());
        assert_eq!(
            records[0].user_id.as_deref(),
            Some("unspecified"),
            "a subject was presented, so the record must not read as anonymous"
        );
    }

    /// Findings carry runtime annotation text the schema deliberately leaves
    /// unpatterned. Coercing it would rewrite the evidence to satisfy a rule
    /// that does not exist.
    #[tokio::test]
    async fn finding_labels_are_recorded_verbatim() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(
            EvalResult {
                allow: false,
                findings: vec![Finding {
                    kind: "secret_detected".to_owned(),
                    label: "AWS access key".to_owned(),
                    severity: Severity::High,
                    confidence: None,
                }],
                ..Default::default()
            },
            dir.path(),
        );

        svc.evaluate(request()).await.expect("deny is a response");

        let records = records(dir.path());
        let findings = records[0].findings.as_ref().expect("findings carried");
        assert_eq!(findings[0].label, "AWS access key");
        assert_eq!(findings[0].kind, "secret_detected");
    }

    /// A denial must record as a denial, carrying the observations behind it.
    /// A deny silently logged as an allow is the worst outcome this whole
    /// integration can produce.
    #[tokio::test]
    async fn a_denied_request_is_recorded_as_a_denial_with_its_findings() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(
            EvalResult {
                allow: false,
                deny_reason: "egress to an unapproved host".to_owned(),
                verdict: Verdict::Escalate,
                findings: vec![Finding {
                    kind: "content.class".to_owned(),
                    label: "secret".to_owned(),
                    severity: Severity::High,
                    confidence: Some(91),
                }],
                ..Default::default()
            },
            dir.path(),
        );

        svc.evaluate(request()).await.expect("deny is a response");

        let records = records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authorization);
        assert_eq!(r.decision, Some(apf_audit::Decision::Deny));
        assert_eq!(r.verdict, Some(apf_audit::Verdict::Escalate));
        let findings = r.findings.as_ref().expect("findings are carried");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "secret");
        assert_eq!(findings[0].confidence, Some(91));
    }

    /// A caller must not be able to erase the record of their own request by
    /// malforming the fields that reach it.
    #[tokio::test]
    async fn a_hostile_request_cannot_suppress_its_own_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = service(EvalResult::default(), dir.path());

        for hostile in [
            "../../etc/shadow",
            "clé_secrète",
            "!!!",
            "",
            &"x".repeat(2000),
        ] {
            svc.evaluate(Request::new(EvaluateRequest {
                resource: Some(ResourceRef {
                    class: hostile.to_owned(),
                    ..Default::default()
                }),
                verb: hostile.to_owned(),
                ..Default::default()
            }))
            .await
            .expect("evaluation still answers");
        }

        // Not erased is not enough: without these a bare fallback for every
        // request would pass, which is degradation, not evidence.
        let records = records(dir.path());
        assert_eq!(records.len(), 5, "every request left a record");
        for r in &records {
            assert_eq!(r.event_type, apf_audit::EventType::Authorization);
            assert_eq!(r.decision, Some(apf_audit::Decision::Allow));
            // The primary path, not the degraded fallback: coercion should
            // rescue these, and `reason` is set only when it could not.
            assert_eq!(
                r.reason, None,
                "coercion should rescue the request, not fall back"
            );
        }
    }
}
