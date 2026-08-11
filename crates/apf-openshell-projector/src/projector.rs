// SPDX-License-Identifier: Apache-2.0
//! `OpenShell` projector — projects the canonical APF IR to the `OpenShell`
//! substrate's surfaces: `openshell.sandbox.v1` (proto bytes from each
//! `SandboxPolicy`), `openshell.provider-profile.v1` (a `ProviderProfile` YAML
//! composed from each canonical `Provider`, plus a passthrough of native
//! `ProviderProfile` YAML), `apf.policy-rules.v1` (compiled `PolicyRule`
//! entries), and `apf.policy-annotators.v1` (compiled `PolicyAnnotator` entries).
//!
//! The canonical and sandbox-target schemas are structurally aligned; the
//! non-trivial differences are:
//!   - The target has a top-level `version` field (schema version, always 1).
//!   - The target `NetworkEndpoint` has `advisor_proposed` (internal runtime
//!     state never authored in policy; set to `false` on every lowering).
//!   - The canonical IR is nested (`SandboxPolicy { metadata, spec }`); the
//!     target is flat (`SandboxPolicy { version, filesystem, … }`).

use std::collections::BTreeMap;

use apf_proto::ir;
use apf_proto::openshell_sandbox as os;
use prost::Message;

use apf_compiler::{CanonicalPolicy, CompiledSurface, ProjectError, Projector};

/// Substrate identifier selected against `[compiler] targets`.
pub const TARGET: &str = "openshell";

pub const SURFACE_ID: &str = "openshell.sandbox.v1";
/// Surface kind for `ProviderProfile` passthrough documents.
const SURFACE_PROVIDER_PROFILE: &str = "openshell.provider-profile.v1";
/// Surface kind for compiled `PolicyRule` entries.
const SURFACE_POLICY_RULES: &str = "apf.policy-rules.v1";
/// Surface kind for compiled `PolicyAnnotator` entries.
const SURFACE_POLICY_ANNOTATORS: &str = "apf.policy-annotators.v1";
/// Surface kind for compiled `PolicyEffect` entries.
const SURFACE_POLICY_EFFECTS: &str = "apf.policy-effects.v1";
/// Surface kind for compiled `PolicyFinding` entries.
const SURFACE_POLICY_FINDINGS: &str = "apf.policy-findings.v1";

const OPENSHELL_POLICY_VERSION: u32 = 1;

pub struct OpenShellProjector;

impl Projector for OpenShellProjector {
    fn target(&self) -> &str {
        TARGET
    }

    fn project(&self, p: &CanonicalPolicy) -> Result<Vec<CompiledSurface>, ProjectError> {
        let mut surfaces = Vec::new();

        // SandboxPolicy → openshell.sandbox.v1 (proto bytes).
        for (name, sandbox) in &p.sandbox_policies {
            let spec = sandbox.spec.as_ref().ok_or_else(|| ProjectError {
                target: TARGET.to_string(),
                surface: SURFACE_ID.to_string(),
                cause: format!("SandboxPolicy '{name}' has no spec"),
            })?;
            let middleware = p.sandbox_middleware.get(name);
            surfaces.push(CompiledSurface {
                kind: SURFACE_ID.to_string(),
                name: name.clone(),
                bytes: lower_spec_with_middleware(spec, middleware).encode_to_vec(),
            });
        }

        // ProviderProfiles → openshell.provider-profile.v1 (passthrough; raw
        // YAML bytes).
        //
        // WHY PASSTHROUGH IS CORRECT: The consumer (OpenShell gateway) has its
        // own YAML-to-proto deserializer for ProviderProfile documents. The
        // gateway's ImportProviderProfiles endpoint parses YAML into
        // `openshell.v1.ProviderProfile` proto messages internally. Vendoring
        // the full openshell.proto (~1800 lines, 30+ message types) into APF
        // solely to emit proto-encoded bytes would couple the PDP to the
        // gateway's internal schema evolution cadence without any consumer
        // benefit — the gateway would need to re-parse the proto bytes back
        // into its own generated types anyway.
        //
        // Contract: GetDocument(kind="openshell.provider-profile.v1", name=<id>)
        // returns the YAML bytes verbatim. The gateway is authoritative for
        // interpreting them.
        for (name, body) in &p.provider_profiles {
            surfaces.push(CompiledSurface {
                kind: SURFACE_PROVIDER_PROFILE.to_string(),
                name: name.clone(),
                bytes: body.clone(),
            });
        }

        // Provider → openshell.provider-profile.v1 (composed YAML). This is
        // additive to the passthrough above; the passthrough retires once
        // fixtures author Providers instead of native profiles. A name that
        // collides with a passthrough entry is a bundle authoring error — the
        // composed profile takes precedence and the passthrough copy is dropped.
        let passthrough_names: std::collections::BTreeSet<&String> =
            p.provider_profiles.keys().collect();
        for (name, provider) in &p.providers {
            let bytes =
                crate::provider::compose(provider).map_err(|cause| ProjectError {
                    target: TARGET.to_string(),
                    surface: SURFACE_PROVIDER_PROFILE.to_string(),
                    cause: format!("provider '{name}': {cause}"),
                })?;
            if passthrough_names.contains(name) {
                surfaces.retain(|s| !(s.kind == SURFACE_PROVIDER_PROFILE && &s.name == name));
            }
            surfaces.push(CompiledSurface {
                kind: SURFACE_PROVIDER_PROFILE.to_string(),
                name: name.clone(),
                bytes,
            });
        }

        // PolicyRule → apf.policy-rules.v1 (JSON array of compiled entries),
        // loaded by the policy gateway's middleware at startup.
        if !p.policy_rules.is_empty() {
            surfaces.push(CompiledSurface {
                kind: SURFACE_POLICY_RULES.to_string(),
                name: "default".to_string(),
                bytes: build_policy_rules_projection(&p.policy_rules),
            });
        }

        // PolicyAnnotator → apf.policy-annotators.v1 (JSON array of compiled
        // entries), consumed alongside apf.policy-rules.v1 by the Cedar
        // engine's annotator stage.
        if !p.policy_annotators.is_empty() {
            surfaces.push(CompiledSurface {
                kind: SURFACE_POLICY_ANNOTATORS.to_string(),
                name: "default".to_string(),
                bytes: build_policy_annotators_projection(&p.policy_annotators),
            });
        }

        // PolicyEffect → apf.policy-effects.v1 and PolicyFinding →
        // apf.policy-findings.v1 (JSON arrays of compiled entries), consumed
        // alongside apf.policy-rules.v1 by the Cedar engine's effect stage.
        if !p.policy_effects.is_empty() {
            surfaces.push(CompiledSurface {
                kind: SURFACE_POLICY_EFFECTS.to_string(),
                name: "default".to_string(),
                bytes: build_policy_effects_projection(&p.policy_effects),
            });
        }
        if !p.policy_findings.is_empty() {
            surfaces.push(CompiledSurface {
                kind: SURFACE_POLICY_FINDINGS.to_string(),
                name: "default".to_string(),
                bytes: build_policy_findings_projection(&p.policy_findings),
            });
        }

        Ok(surfaces)
    }
}

/// Build the `apf.policy-effects.v1` projection: the compiled `PolicyEffect`
/// entries in bundle order, in the authoring field vocabulary so consumers
/// can reload them without this crate's types.
fn build_policy_effects_projection(effects: &[ir::PolicyEffect]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = effects
        .iter()
        .map(|e| {
            let name = e.metadata.as_ref().map_or("", |m| m.name.as_str());
            let desc = e.metadata.as_ref().map_or("", |m| m.description.as_str());
            let mut entry = serde_json::Map::new();
            entry.insert("name".into(), name.into());
            entry.insert("description".into(), desc.into());
            if let Some(spec) = &e.spec {
                let verdict_str = match ir::Verdict::try_from(spec.verdict).unwrap_or_default() {
                    ir::Verdict::Unspecified | ir::Verdict::Allow => "allow",
                    ir::Verdict::Warn => "warn",
                    ir::Verdict::Escalate => "escalate",
                };
                entry.insert("verdict".into(), verdict_str.into());
                if let Some(reason) = &spec.reason {
                    entry.insert("reason".into(), reason.clone().into());
                }
                if let Some(message) = &spec.message {
                    entry.insert("message".into(), message.clone().into());
                }
                if let Some(body) = &spec.body {
                    let mut body_json = serde_json::Map::new();
                    if let Some(replace) = &body.replace {
                        body_json.insert("replace".into(), replace.clone().into());
                    }
                    if !body.patches.is_empty() {
                        let patches: Vec<serde_json::Value> = body
                            .patches
                            .iter()
                            .map(|p| {
                                let mut patch = serde_json::Map::new();
                                let op_str = match ir::PatchOp::try_from(p.op).unwrap_or_default() {
                                    ir::PatchOp::Unspecified | ir::PatchOp::Replace => "replace",
                                    ir::PatchOp::Add => "add",
                                    ir::PatchOp::Remove => "remove",
                                };
                                patch.insert("op".into(), op_str.into());
                                patch.insert("path".into(), p.path.clone().into());
                                if let Some(value) = &p.value {
                                    patch.insert(
                                        "value".into(),
                                        apf_proto::json::prost_value_to_json(value),
                                    );
                                }
                                if let Some(source) = &p.source {
                                    patch.insert("source".into(), source.clone().into());
                                }
                                serde_json::Value::Object(patch)
                            })
                            .collect();
                        body_json.insert("patches".into(), patches.into());
                    }
                    entry.insert("body".into(), serde_json::Value::Object(body_json));
                }
                if !spec.headers.is_empty() {
                    let headers: Vec<serde_json::Value> = spec
                        .headers
                        .iter()
                        .map(|h| {
                            let mut header = serde_json::Map::new();
                            header.insert("name".into(), h.name.clone().into());
                            let action_str =
                                match ir::HeaderAction::try_from(h.action).unwrap_or_default() {
                                    ir::HeaderAction::Unspecified | ir::HeaderAction::Set => "set",
                                    ir::HeaderAction::Add => "add",
                                    ir::HeaderAction::Remove => "remove",
                                };
                            header.insert("action".into(), action_str.into());
                            if let Some(value) = &h.value {
                                header.insert("value".into(), value.clone().into());
                            }
                            if let Some(source) = &h.source {
                                header.insert("source".into(), source.clone().into());
                            }
                            serde_json::Value::Object(header)
                        })
                        .collect();
                    entry.insert("headers".into(), headers.into());
                }
                if let Some(finding_ref) = &spec.finding {
                    match &finding_ref.kind {
                        Some(ir::finding_ref::Kind::Reference(r)) => {
                            entry.insert("finding".into(), r.clone().into());
                        }
                        Some(ir::finding_ref::Kind::Inline(inline)) => {
                            let mut finding = serde_json::Map::new();
                            finding.insert("type".into(), inline.kind.clone().into());
                            if let Some(label) = &inline.label {
                                finding.insert("label".into(), label.clone().into());
                            }
                            let sev_str =
                                match ir::Severity::try_from(inline.severity).unwrap_or_default() {
                                    ir::Severity::Unspecified | ir::Severity::Low => "low",
                                    ir::Severity::Medium => "medium",
                                    ir::Severity::High => "high",
                                    ir::Severity::Critical => "critical",
                                };
                            finding.insert("severity".into(), sev_str.into());
                            if let Some(confidence) = inline.confidence {
                                finding.insert("confidence".into(), confidence.into());
                            }
                            if let Some(source) = &inline.label_source {
                                finding.insert("label_source".into(), source.clone().into());
                            }
                            entry.insert("finding".into(), serde_json::Value::Object(finding));
                        }
                        None => {}
                    }
                }
            }
            serde_json::Value::Object(entry)
        })
        .collect();
    serde_json::to_vec(&entries).unwrap_or_default()
}

/// Build the `apf.policy-findings.v1` projection: the compiled
/// `PolicyFinding` entries in bundle order, in the authoring field
/// vocabulary.
fn build_policy_findings_projection(findings: &[ir::PolicyFinding]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let name = f.metadata.as_ref().map_or("", |m| m.name.as_str());
            let desc = f.metadata.as_ref().map_or("", |m| m.description.as_str());
            let mut entry = serde_json::Map::new();
            entry.insert("name".into(), name.into());
            entry.insert("description".into(), desc.into());
            if let Some(spec) = &f.spec {
                entry.insert("type".into(), spec.kind.clone().into());
                let sev_str = match ir::Severity::try_from(spec.severity).unwrap_or_default() {
                    ir::Severity::Unspecified | ir::Severity::Low => "low",
                    ir::Severity::Medium => "medium",
                    ir::Severity::High => "high",
                    ir::Severity::Critical => "critical",
                };
                entry.insert("severity".into(), sev_str.into());
                if let Some(label) = &spec.label {
                    entry.insert("label".into(), label.clone().into());
                }
                if let Some(source) = &spec.label_source {
                    entry.insert("label_source".into(), source.clone().into());
                }
            }
            serde_json::Value::Object(entry)
        })
        .collect();
    serde_json::to_vec(&entries).unwrap_or_default()
}

/// Build the `apf.policy-rules.v1` projection: the compiled `PolicyRule`
/// entries in bundle order, preserving each rule's evaluation language.
fn build_policy_rules_projection(rules: &[ir::PolicyRule]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            let spec = r.spec.clone().unwrap_or_default();
            serde_json::json!({
                "name": r.metadata.as_ref().map_or("", |m| m.name.as_str()),
                "language": spec.language,
                "schema": spec.schema,
                "definition": spec.definition,
                "data": spec
                    .data
                    .as_ref()
                    .map_or(serde_json::Value::Null, apf_proto::json::struct_to_json),
            })
        })
        .collect();
    serde_json::to_vec(&entries).unwrap_or_default()
}

/// Build the `apf.policy-annotators.v1` projection: the compiled
/// `PolicyAnnotator` entries in bundle order, in the authoring field
/// vocabulary (op names, output types) so consumers can reload them without
/// this crate's types.
fn build_policy_annotators_projection(
    annotators: &[apf_compiler::frontend::PolicyAnnotator],
) -> Vec<u8> {
    use apf_policy_eval::{AnnotationOp, AnnotationOutput, SetTrueIf, SetValueFrom};

    let entries: Vec<serde_json::Value> = annotators
        .iter()
        .map(|a| {
            let annotations: Vec<serde_json::Value> = a
                .annotations
                .iter()
                .map(|spec| {
                    let rules: Vec<serde_json::Value> = spec
                        .rules
                        .iter()
                        .map(|r| {
                            let mut rule = serde_json::Map::new();
                            rule.insert("field".into(), r.field.clone().into());
                            let op = match r.op {
                                AnnotationOp::RegexMatch => "regex_match",
                                AnnotationOp::Equals => "equals",
                                AnnotationOp::EndsWith => "endswith",
                                AnnotationOp::StartsWith => "startswith",
                                AnnotationOp::Contains => "contains",
                                AnnotationOp::Length => "length",
                                AnnotationOp::Gte => "gte",
                                AnnotationOp::Lte => "lte",
                                AnnotationOp::Passthrough => "passthrough",
                            };
                            rule.insert("op".into(), op.into());
                            let operands = [
                                ("pattern", &r.pattern),
                                ("value", &r.value),
                                ("suffix", &r.suffix),
                                ("prefix", &r.prefix),
                                ("substring", &r.substring),
                            ];
                            for (key, operand) in operands {
                                if let Some(v) = operand {
                                    rule.insert(key.into(), v.clone().into());
                                }
                            }
                            if let Some(t) = r.threshold {
                                rule.insert("threshold".into(), t.into());
                            }
                            serde_json::Value::Object(rule)
                        })
                        .collect();
                    serde_json::json!({
                        "name": spec.name,
                        "output": match spec.output {
                            AnnotationOutput::Bool => "bool",
                            AnnotationOutput::String => "string",
                            AnnotationOutput::Integer => "integer",
                        },
                        "set_true_if": match spec.set_true_if {
                            SetTrueIf::Any => "any",
                            SetTrueIf::All => "all",
                        },
                        "set_value_from": match spec.set_value_from {
                            SetValueFrom::FirstMatch => "first_match",
                        },
                        "rules": rules,
                    })
                })
                .collect();
            serde_json::json!({
                "name": a.name,
                "description": a.description,
                "annotations": annotations,
            })
        })
        .collect();
    serde_json::to_vec(&entries).unwrap_or_default()
}

fn lower_spec_with_middleware(
    spec: &ir::SandboxPolicySpec,
    middleware: Option<
        &BTreeMap<String, apf_compiler::frontend::NetworkMiddlewareConfigDef>,
    >,
) -> os::SandboxPolicy {
    os::SandboxPolicy {
        version: OPENSHELL_POLICY_VERSION,
        filesystem: spec.filesystem.as_ref().map(|fs| os::FilesystemPolicy {
            include_workdir: fs.include_workdir,
            read_only: fs.read_only.clone(),
            read_write: fs.read_write.clone(),
        }),
        landlock: spec.landlock.as_ref().map(|ll| os::LandlockPolicy {
            compatibility: ll.compatibility.clone(),
        }),
        process: spec.process.as_ref().map(|p| os::ProcessPolicy {
            run_as_user: p.run_as_user.clone(),
            run_as_group: p.run_as_group.clone(),
        }),
        network_policies: spec
            .network_policies
            .iter()
            .map(|(key, rule)| (key.clone(), lower_rule(rule)))
            .collect(),
        network_middlewares: middleware
            .map(|mw| {
                mw.iter()
                    .map(|(key, cfg)| {
                        (
                            key.clone(),
                            os::NetworkMiddlewareConfig {
                                name: cfg.name.clone(),
                                middleware: cfg.middleware.clone(),
                                on_error: cfg.on_error.clone(),
                                order: cfg.order,
                                endpoints: Some(os::MiddlewareEndpointSelector {
                                    include: cfg.endpoints.include.clone(),
                                    exclude: cfg.endpoints.exclude.clone(),
                                }),
                                config: None,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn lower_rule(rule: &ir::NetworkPolicyRule) -> os::NetworkPolicyRule {
    os::NetworkPolicyRule {
        name: rule.name.clone(),
        endpoints: rule.endpoints.iter().map(lower_endpoint).collect(),
        binaries: rule
            .binaries
            .iter()
            .map(|b| os::NetworkBinary {
                path: b.path.clone(),
                ..Default::default()
            })
            .collect(),
    }
}

fn lower_endpoint(e: &ir::NetworkEndpoint) -> os::NetworkEndpoint {
    os::NetworkEndpoint {
        host: e.host.clone(),
        path: e.path.clone(),
        port: e.port,
        ports: e.ports.clone(),
        protocol: e.protocol.clone(),
        tls: e.tls.clone(),
        enforcement: e.enforcement.clone(),
        access: e.access.clone(),
        rules: e.rules.iter().map(lower_l7rule).collect(),
        allowed_ips: e.allowed_ips.clone(),
        deny_rules: e.deny_rules.iter().map(lower_deny_rule).collect(),
        allow_encoded_slash: e.allow_encoded_slash,
        websocket_credential_rewrite: e.websocket_credential_rewrite,
        request_body_credential_rewrite: e.request_body_credential_rewrite,
        advisor_proposed: false,
        persisted_queries: e.persisted_queries.clone(),
        graphql_persisted_queries: e
            .graphql_persisted_queries
            .iter()
            .map(|(k, op)| {
                (
                    k.clone(),
                    os::GraphqlOperation {
                        operation_type: op.operation_type.clone(),
                        operation_name: op.operation_name.clone(),
                        fields: op.fields.clone(),
                    },
                )
            })
            .collect(),
        graphql_max_body_bytes: e.graphql_max_body_bytes,
        json_rpc_max_body_bytes: e.json_rpc_max_body_bytes,
        mcp: e.mcp.as_ref().map(|m| os::McpOptions {
            strict_tool_names: m.strict_tool_names,
            allow_all_known_mcp_methods: m.allow_all_known_mcp_methods,
        }),
        credential_signing: String::new(),
        signing_region: String::new(),
        signing_service: String::new(),
    }
}

fn lower_l7rule(r: &ir::L7Rule) -> os::L7Rule {
    os::L7Rule {
        allow: r.allow.as_ref().map(|a| os::L7Allow {
            method: a.method.clone(),
            path: a.path.clone(),
            command: a.command.clone(),
            operation_type: a.operation_type.clone(),
            operation_name: a.operation_name.clone(),
            fields: a.fields.clone(),
            query: a
                .query
                .iter()
                .map(|(k, m)| (k.clone(), lower_query(m)))
                .collect(),
            params: a
                .params
                .iter()
                .map(|(k, m)| (k.clone(), lower_query(m)))
                .collect(),
        }),
    }
}

fn lower_deny_rule(d: &ir::L7DenyRule) -> os::L7DenyRule {
    os::L7DenyRule {
        method: d.method.clone(),
        path: d.path.clone(),
        command: d.command.clone(),
        operation_type: d.operation_type.clone(),
        operation_name: d.operation_name.clone(),
        fields: d.fields.clone(),
        query: d
            .query
            .iter()
            .map(|(k, m)| (k.clone(), lower_query(m)))
            .collect(),
        params: d
            .params
            .iter()
            .map(|(k, m)| (k.clone(), lower_query(m)))
            .collect(),
    }
}

fn lower_query(m: &ir::L7QueryMatcher) -> os::L7QueryMatcher {
    os::L7QueryMatcher {
        glob: m.glob.clone(),
        any: m.any.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_compiler::frontend;

    const STUB: &str =
        include_str!("../../../examples/demo-bundle/sandbox/default-policy.yaml");

    fn project_default(ir: ir::SandboxPolicy) -> Vec<u8> {
        let mut p = CanonicalPolicy::default();
        p.sandbox_policies.insert("default".to_string(), ir);
        let surfaces = OpenShellProjector.project(&p).expect("project");
        surfaces
            .into_iter()
            .find(|s| s.kind == SURFACE_ID && s.name == "default")
            .expect("sandbox surface")
            .bytes
    }

    fn parse_and_lower(yaml: &str) -> os::SandboxPolicy {
        let ir = frontend::parse(yaml.as_bytes()).expect("frontend parse");
        os::SandboxPolicy::decode(project_default(ir).as_slice()).expect("decode")
    }

    #[test]
    fn lowers_stub_fixture() {
        let p = parse_and_lower(STUB);
        assert_eq!(p.version, 1);
        let fs = p.filesystem.expect("filesystem present");
        assert!(fs.include_workdir);
        assert_eq!(
            fs.read_only,
            vec![
                "/usr",
                "/lib",
                "/proc",
                "/dev/urandom",
                "/app",
                "/etc",
                "/var/log"
            ]
        );
        assert_eq!(fs.read_write, vec!["/sandbox", "/tmp", "/dev/null"]);
        let ll = p.landlock.expect("landlock present");
        assert_eq!(ll.compatibility, "best_effort");
        let proc_p = p.process.expect("process present");
        assert_eq!(proc_p.run_as_user, "sandbox");
        assert!(!p.network_policies.is_empty());
        for (key, np) in &p.network_policies {
            assert!(!np.name.is_empty(), "policy {key} has a name");
            let ep = np.endpoints.first().expect("endpoint present");
            assert!(!ep.host.is_empty());
            assert!(ep.port > 0);
            assert_eq!(ep.ports, vec![ep.port]);
            assert!(!ep.advisor_proposed, "advisor_proposed must be false");
        }
    }

    #[test]
    fn lowers_rev2_fixture() {
        let yaml = r#"
apiVersion: nvidia.agent-policy-fabric.sandbox/v1alpha1
kind: SandboxPolicy
metadata:
  name: default
spec:
  filesystem:
    include_workdir: true
    read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log, /opt]
    read_write: [/sandbox, /tmp, /dev/null]
  landlock:
    compatibility: best_effort
  process:
    run_as_user: sandbox
    run_as_group: sandbox
  network_policies:
    github:
      name: github
      binaries:
        - path: /usr/bin/curl
      endpoints:
        - host: api.github.com
          port: 443
          protocol: rest
          enforcement: enforce
          rules:
            - allow: {method: GET, path: /zen}
            - allow: {method: GET, path: /octocat}
"#;
        let p = parse_and_lower(yaml);
        let fs = p.filesystem.unwrap();
        assert_eq!(
            fs.read_only,
            vec![
                "/usr",
                "/lib",
                "/proc",
                "/dev/urandom",
                "/app",
                "/etc",
                "/var/log",
                "/opt"
            ]
        );
        let np = p.network_policies.get("github").expect("github policy");
        let ep = &np.endpoints[0];
        assert_eq!(ep.protocol, "rest");
        assert_eq!(ep.host, "api.github.com");
    }

    fn policy_rule(
        name: &str,
        schema: Option<&str>,
        data: Option<serde_json::Value>,
    ) -> ir::PolicyRule {
        let data = data.map(|v| {
            match apf_proto::json::json_to_proto_value(&v)
                .expect("proto value")
                .kind
            {
                Some(prost_types::value::Kind::StructValue(s)) => s,
                other => panic!("expected struct, got {other:?}"),
            }
        });
        ir::PolicyRule {
            metadata: Some(ir::ObjectMeta {
                name: name.to_string(),
                ..Default::default()
            }),
            spec: Some(ir::PolicyRuleSpec {
                language: "cedar".to_string(),
                schema: schema.map(str::to_string),
                definition: "permit(principal, action, resource);".to_string(),
                data,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn projects_policy_rules_surface() {
        let mut p = CanonicalPolicy::default();
        p.policy_rules.push(policy_rule(
            "outlook-grants",
            None,
            Some(serde_json::json!({"grants": []})),
        ));
        p.policy_rules.push(policy_rule(
            "typed-rule",
            Some("namespace APF { entity User; }"),
            None,
        ));
        let surfaces = OpenShellProjector.project(&p).expect("project");
        let surface = surfaces
            .iter()
            .find(|s| s.kind == "apf.policy-rules.v1" && s.name == "default")
            .expect("policy-rules surface");
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&surface.bytes).expect("json array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["name"], "outlook-grants");
        assert_eq!(entries[0]["language"], "cedar");
        assert_eq!(entries[0]["schema"], serde_json::Value::Null);
        assert!(
            entries[0]["definition"]
                .as_str()
                .unwrap()
                .contains("permit")
        );
        assert_eq!(entries[0]["data"]["grants"], serde_json::json!([]));
        assert_eq!(entries[1]["name"], "typed-rule");
        assert_eq!(entries[1]["schema"], "namespace APF { entity User; }");

        // Downstream consumers reload this surface by exact shape: each entry
        // is {name, language, schema, definition, data}.
        let expected = concat!(
            r#"[{"name":"outlook-grants","language":"cedar","schema":null,"definition":"permit(principal, action, resource);","data":{"grants":[]}},"#,
            r#"{"name":"typed-rule","language":"cedar","schema":"namespace APF { entity User; }","definition":"permit(principal, action, resource);","data":null}]"#
        );
        assert_eq!(std::str::from_utf8(&surface.bytes).unwrap(), expected);
    }

    #[test]
    fn no_policy_rules_no_surface() {
        let p = CanonicalPolicy::default();
        let surfaces = OpenShellProjector.project(&p).expect("project");
        assert!(!surfaces.iter().any(|s| s.kind == "apf.policy-rules.v1"));
        assert!(
            !surfaces
                .iter()
                .any(|s| s.kind == "apf.policy-annotators.v1")
        );
    }

    #[test]
    fn projects_policy_annotators_surface() {
        let mut p = CanonicalPolicy::default();
        p.policy_annotators
            .push(apf_compiler::frontend::PolicyAnnotator {
                name: "secret-detector".to_string(),
                description: "Detects credentials".to_string(),
                annotations: vec![apf_policy_eval::AnnotationSpec {
                    name: "secret_detected".to_string(),
                    output: apf_policy_eval::AnnotationOutput::Bool,
                    set_true_if: apf_policy_eval::SetTrueIf::Any,
                    set_value_from: apf_policy_eval::SetValueFrom::FirstMatch,
                    rules: vec![apf_policy_eval::AnnotationRule {
                        field: "body_text".to_string(),
                        op: apf_policy_eval::AnnotationOp::RegexMatch,
                        pattern: Some("AKIA[0-9A-Z]{16}".to_string()),
                        ..apf_policy_eval::AnnotationRule::default()
                    }],
                }],
            });
        let surfaces = OpenShellProjector.project(&p).expect("project");
        let surface = surfaces
            .iter()
            .find(|s| s.kind == "apf.policy-annotators.v1" && s.name == "default")
            .expect("policy-annotators surface");
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&surface.bytes).expect("json array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "secret-detector");
        let ann = &entries[0]["annotations"][0];
        assert_eq!(ann["name"], "secret_detected");
        assert_eq!(ann["output"], "bool");
        assert_eq!(ann["set_true_if"], "any");
        let rule = &ann["rules"][0];
        assert_eq!(rule["field"], "body_text");
        assert_eq!(rule["op"], "regex_match");
        assert_eq!(rule["pattern"], "AKIA[0-9A-Z]{16}");
        // Absent operands are omitted, not serialized as null.
        assert!(rule.get("suffix").is_none());
        assert!(rule.get("threshold").is_none());
    }

    #[test]
    fn projects_policy_effects_and_findings_surfaces() {
        let mut p = CanonicalPolicy::default();
        p.policy_effects.push(ir::PolicyEffect {
            metadata: Some(ir::ObjectMeta {
                name: "redact-body".to_string(),
                description: "Redact leaked secrets".to_string(),
                ..Default::default()
            }),
            spec: Some(ir::PolicyEffectSpec {
                description: "Redact leaked secrets".to_string(),
                verdict: ir::Verdict::Warn as i32,
                reason: Some("secret_in_body".to_string()),
                message: None,
                body: Some(ir::BodySpec {
                    replace: Some("[REDACTED]".to_string()),
                    patches: Vec::new(),
                }),
                headers: vec![ir::HeaderSpec {
                    name: "X-APF-Event".to_string(),
                    action: ir::HeaderAction::Set as i32,
                    value: None,
                    source: Some("context.annotations.secret_kind".to_string()),
                }],
                finding: Some(ir::FindingRef {
                    kind: Some(ir::finding_ref::Kind::Reference(
                        "secret-detected".to_string(),
                    )),
                }),
            }),
        });
        p.policy_findings.push(ir::PolicyFinding {
            metadata: Some(ir::ObjectMeta {
                name: "secret-detected".to_string(),
                description: String::new(),
                ..Default::default()
            }),
            spec: Some(ir::PolicyFindingSpec {
                description: String::new(),
                kind: "secret_detected".to_string(),
                severity: ir::Severity::Critical as i32,
                label: None,
                label_source: Some("context.annotations.secret_kind".to_string()),
            }),
        });

        let surfaces = OpenShellProjector.project(&p).expect("project");
        let effects = surfaces
            .iter()
            .find(|s| s.kind == "apf.policy-effects.v1" && s.name == "default")
            .expect("policy-effects surface");
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&effects.bytes).expect("json array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "redact-body");
        assert_eq!(entries[0]["verdict"], "warn");
        assert_eq!(entries[0]["reason"], "secret_in_body");
        // Absent fields are omitted, not serialized as null.
        assert!(entries[0].get("message").is_none());
        assert_eq!(entries[0]["body"]["replace"], "[REDACTED]");
        assert!(entries[0]["body"].get("patches").is_none());
        assert_eq!(entries[0]["headers"][0]["action"], "set");
        assert_eq!(
            entries[0]["headers"][0]["source"],
            "context.annotations.secret_kind"
        );
        assert_eq!(entries[0]["finding"], "secret-detected");

        let findings = surfaces
            .iter()
            .find(|s| s.kind == "apf.policy-findings.v1" && s.name == "default")
            .expect("policy-findings surface");
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&findings.bytes).expect("json array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "secret-detected");
        assert_eq!(entries[0]["type"], "secret_detected");
        assert_eq!(entries[0]["severity"], "critical");
        assert_eq!(
            entries[0]["label_source"],
            "context.annotations.secret_kind"
        );
    }

    #[test]
    fn no_policy_effects_no_surfaces() {
        let p = CanonicalPolicy::default();
        let surfaces = OpenShellProjector.project(&p).expect("project");
        assert!(!surfaces.iter().any(|s| s.kind == "apf.policy-effects.v1"));
        assert!(!surfaces.iter().any(|s| s.kind == "apf.policy-findings.v1"));
    }

    #[test]
    fn proto_round_trips() {
        let ir = frontend::parse(STUB.as_bytes()).expect("parse");
        let bytes = project_default(ir);
        assert!(!bytes.is_empty());
        let decoded = os::SandboxPolicy::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded.version, 1);
        assert_eq!(
            decoded.filesystem.unwrap().read_only,
            vec![
                "/usr",
                "/lib",
                "/proc",
                "/dev/urandom",
                "/app",
                "/etc",
                "/var/log"
            ]
        );
    }
}
