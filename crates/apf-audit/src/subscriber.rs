// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::{Event, Id, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

const APF_AUDIT_OBSERVABILITY_TARGET: &str = "apf.audit.obs";
const MAX_OBSERVATION_VALUE_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApfObservationKind {
    Span,
    Event,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfObservation {
    pub kind: ApfObservationKind,
    pub name: String,
    pub target: String,
    pub level: String,
    pub fields: BTreeMap<String, String>,
}

pub trait ApfObservationSink: Send + Sync + 'static {
    fn record(&self, observation: ApfObservation);
}

#[derive(Debug, Clone, Default)]
#[cfg(test)]
struct SharedObservationSink {
    observations: Arc<Mutex<Vec<ApfObservation>>>,
}

#[cfg(test)]
impl SharedObservationSink {
    #[must_use]
    pub fn observations(&self) -> Vec<ApfObservation> {
        self.observations
            .lock()
            .expect("observation sink lock should not be poisoned")
            .clone()
    }
}

#[cfg(test)]
impl ApfObservationSink for SharedObservationSink {
    fn record(&self, observation: ApfObservation) {
        self.observations
            .lock()
            .expect("observation sink lock should not be poisoned")
            .push(observation);
    }
}

#[derive(Debug, Clone)]
pub struct ApfTracingLayer<Sink> {
    sink: Sink,
}

#[cfg(test)]
impl ApfTracingLayer<SharedObservationSink> {
    fn capture() -> (Self, SharedObservationSink) {
        let sink = SharedObservationSink::default();
        (Self::new(sink.clone()), sink)
    }
}

impl<Sink> ApfTracingLayer<Sink>
where
    Sink: ApfObservationSink,
{
    #[must_use]
    pub fn new(sink: Sink) -> Self {
        Self { sink }
    }

    fn record_observation(&self, observation: ApfObservation) {
        self.sink.record(observation);
    }
}

impl<Sink, S> Layer<S> for ApfTracingLayer<Sink>
where
    Sink: ApfObservationSink,
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        if !is_apf_observability_target(metadata.target()) {
            return;
        }

        let mut visitor = SafeFieldVisitor::default();
        attrs.record(&mut visitor);
        let fields = visitor.into_fields();

        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(fields.clone()));
        }

        self.record_observation(ApfObservation {
            kind: ApfObservationKind::Span,
            name: metadata.name().to_owned(),
            target: metadata.target().to_owned(),
            level: metadata.level().to_string(),
            fields,
        });
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let metadata = span.metadata();
        if !is_apf_observability_target(metadata.target()) {
            return;
        }

        let mut visitor = SafeFieldVisitor::default();
        values.record(&mut visitor);
        let fields = visitor.into_fields();

        let mut extensions = span.extensions_mut();
        let state = extensions
            .get_mut::<SpanFields>()
            .expect("APF span fields should be inserted at span creation");
        state.0.extend(fields);

        self.record_observation(ApfObservation {
            kind: ApfObservationKind::Span,
            name: metadata.name().to_owned(),
            target: metadata.target().to_owned(),
            level: metadata.level().to_string(),
            fields: state.0.clone(),
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if !is_apf_observability_target(metadata.target()) {
            return;
        }

        let mut visitor = SafeFieldVisitor::default();
        event.record(&mut visitor);
        let mut fields = visitor.into_fields();
        merge_span_fields(&mut fields, event, &ctx);
        let name = observation_name(metadata.name(), &mut fields);

        self.record_observation(ApfObservation {
            kind: ApfObservationKind::Event,
            name,
            target: metadata.target().to_owned(),
            level: metadata.level().to_string(),
            fields,
        });
    }
}

#[derive(Debug, Clone)]
struct SpanFields(BTreeMap<String, String>);

#[derive(Default)]
struct SafeFieldVisitor {
    fields: BTreeMap<String, String>,
}

impl SafeFieldVisitor {
    fn record_value(&mut self, field: &Field, value: impl Into<String>) {
        let name = field.name();
        if !is_safe_observation_field(name) {
            return;
        }

        self.fields
            .insert(name.to_owned(), sanitize_observation_value(&value.into()));
    }

    fn into_fields(self) -> BTreeMap<String, String> {
        self.fields
    }
}

impl Visit for SafeFieldVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let name = field.name();
        if !is_safe_observation_field(name) {
            return;
        }

        self.fields.insert(
            name.to_owned(),
            sanitize_observation_value(&format!("{value:?}")),
        );
    }
}

fn merge_span_fields<S>(
    fields: &mut BTreeMap<String, String>,
    event: &Event<'_>,
    ctx: &Context<'_, S>,
) where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    let Some(scope) = ctx.event_scope(event) else {
        return;
    };

    for span in scope.from_root() {
        let extensions = span.extensions();
        if let Some(span_fields) = extensions.get::<SpanFields>() {
            for (key, value) in &span_fields.0 {
                fields.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
}

fn observation_name(metadata_name: &str, fields: &mut BTreeMap<String, String>) -> String {
    let Some(message) = fields.get("message") else {
        return metadata_name.to_owned();
    };

    if matches!(
        message.as_str(),
        "audit_event_written" | "audit_event_failed"
    ) {
        return message.clone();
    }

    fields.remove("message");
    metadata_name.to_owned()
}

fn is_apf_observability_target(target: &str) -> bool {
    target == APF_AUDIT_OBSERVABILITY_TARGET
}

fn is_safe_observation_field(name: &str) -> bool {
    matches!(
        name,
        "agent_id"
            | "causation_id"
            | "correlation_id"
            | "decision_id"
            | "enforcement_point_id"
            | "error_kind"
            | "event_id"
            | "event_type"
            | "message"
            | "bundle_digest"
            | "policy_revision"
            | "provider"
            | "resource_type"
            | "runtime_substrate"
            | "session_id"
            | "span_id"
            | "trace_id"
            | "trust_root_id"
            | "user_id"
            | "verb"
            | "workspace_id"
    )
}

fn sanitize_observation_value(value: &str) -> String {
    if looks_sensitive(value) {
        return "[redacted]".to_owned();
    }

    if value.len() > MAX_OBSERVATION_VALUE_BYTES {
        return format!("<{} bytes>", value.len());
    }

    value.to_owned()
}

fn looks_sensitive(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();

    (lower.starts_with("bearer ") && lower.len() > "bearer ".len() + 12)
        || (lower.starts_with("basic ") && lower.len() > "basic ".len() + 12)
        || lower.contains("-----begin ")
        || trimmed.contains("sk-")
        || trimmed.contains("ghp_")
        || trimmed.contains("xoxb-")
        || trimmed.contains("xoxp-")
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::prelude::*;

    use super::{ApfObservationKind, ApfTracingLayer};
    use crate::{CommonFields, Component, PolicyActivationEvent, TypedAuditEvent, span};

    #[test]
    fn layer_captures_apf_observability_spans_and_events() {
        let (layer, sink) = ApfTracingLayer::capture();
        let subscriber = tracing_subscriber::registry().with(layer);
        let ctx = test_context();

        tracing::subscriber::with_default(subscriber, || {
            let governed_action = span::governed_action(&ctx);
            let _entered = governed_action.enter();

            let _authorize_span = span::authorize(&ctx, "mail.search");
            let event =
                PolicyActivationEvent::new(crate::model::Outcome::Success, "policy.bundle.loaded")
                    .into_audit_event(&ctx)
                    .expect("policy load event should build");
            span::record_audit_written(&event);
        });

        let observations = sink.observations();
        assert!(observations.iter().any(|observation| {
            observation.kind == ApfObservationKind::Span
                && observation.name == "apf.governed_action"
                && observation.fields.get("correlation_id")
                    == Some(&"corr_test_subscriber".to_owned())
        }));
        assert!(observations.iter().any(|observation| {
            observation.kind == ApfObservationKind::Span
                && observation.name == "apf.authorize"
                && observation.fields.get("verb") == Some(&"mail.search".to_owned())
        }));
        assert!(observations.iter().any(|observation| {
            observation.kind == ApfObservationKind::Event
                && observation.name == "audit_event_written"
                && observation.fields.get("event_type") == Some(&"policy_activation".to_owned())
        }));
    }

    #[test]
    fn layer_drops_non_apf_targets_and_unsafe_fields() {
        let (layer, sink) = ApfTracingLayer::capture();
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                target: "not.apf",
                correlation_id = "corr_ignored",
                "not_apf"
            );
            tracing::info!(
                target: "apf.audit.obs",
                correlation_id = "corr_test_subscriber",
                access_token = "secret",
                result_summary = "raw response",
                provider = "Bearer abcdefghijklmnop",
                "custom_message"
            );
        });

        let observations = sink.observations();
        assert_eq!(observations.len(), 1);
        let encoded = format!("{observations:?}");
        assert!(encoded.contains("corr_test_subscriber"));
        assert!(encoded.contains("[redacted]"));
        assert!(!encoded.contains("corr_ignored"));
        assert!(!encoded.contains("access_token"));
        assert!(!encoded.contains("raw response"));
        assert!(!encoded.contains("custom_message"));
    }

    fn test_context() -> CommonFields {
        let mut ctx = CommonFields::new(
            "corr_test_subscriber",
            "user:example",
            "agent:example",
            "workspace:example",
            "session:example",
            "apf-openshell-middleware:local",
            "openshell",
            Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "trustroot:dev",
        );
        ctx.causation_id = Some("req_test_subscriber".to_owned());
        ctx
    }
}
