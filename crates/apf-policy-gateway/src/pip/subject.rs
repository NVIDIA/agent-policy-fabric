// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The evaluation subject a provider receives: the declared paths and the
//! projection of an evaluator input onto them.

use std::fmt;
use std::str::FromStr;

use apf_policy_eval::EvalInput;
use apf_proto::json::json_to_proto_value;
use apf_proto::pip_v1alpha1::{EvaluationSubject, RequestTarget, RuntimeIdentity};
use apf_proto::prost_types::Struct;
use serde::Deserialize;

/// Attestation value for an empty user subject.
pub const SUBJECT_ATTESTATION_NONE: &str = "none";
/// Attestation value for a user subject asserted by the enforcement point.
pub const SUBJECT_ATTESTATION_CALLER: &str = "caller";

/// One field of the evaluation subject a provider may receive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectPath {
    UserSubject,
    Tool,
    Capability,
    Action,
    /// The whole runtime identity block; as a lookup key, the instance id.
    Runtime,
    /// The runtime platform name alone, as a lookup key.
    RuntimePlatform,
    /// One named call argument.
    Arg(String),
    TargetHost,
    TargetMethod,
    TargetPath,
    TargetScheme,
}

impl FromStr for SubjectPath {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "user_subject" => Ok(Self::UserSubject),
            "tool" => Ok(Self::Tool),
            "capability" => Ok(Self::Capability),
            "action" => Ok(Self::Action),
            "runtime" | "runtime.instance_id" => Ok(Self::Runtime),
            "runtime.platform" => Ok(Self::RuntimePlatform),
            "target.host" => Ok(Self::TargetHost),
            "target.method" => Ok(Self::TargetMethod),
            "target.path" => Ok(Self::TargetPath),
            "target.scheme" => Ok(Self::TargetScheme),
            other => match other.strip_prefix("args.") {
                Some(name)
                    if !name.is_empty()
                        && name.len() <= 128
                        && !name.chars().any(|c| c.is_whitespace() || c.is_control()) =>
                {
                    Ok(Self::Arg(name.to_owned()))
                }
                _ => Err(format!("unknown subject path '{other}'")),
            },
        }
    }
}

impl fmt::Display for SubjectPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserSubject => f.write_str("user_subject"),
            Self::Tool => f.write_str("tool"),
            Self::Capability => f.write_str("capability"),
            Self::Action => f.write_str("action"),
            Self::Runtime => f.write_str("runtime"),
            Self::RuntimePlatform => f.write_str("runtime.platform"),
            Self::Arg(name) => write!(f, "args.{name}"),
            Self::TargetHost => f.write_str("target.host"),
            Self::TargetMethod => f.write_str("target.method"),
            Self::TargetPath => f.write_str("target.path"),
            Self::TargetScheme => f.write_str("target.scheme"),
        }
    }
}

impl<'de> Deserialize<'de> for SubjectPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Paths a provider receives when its registration names none: identity and
/// action, never arguments or target.
#[must_use]
pub fn default_subject() -> Vec<SubjectPath> {
    vec![
        SubjectPath::UserSubject,
        SubjectPath::Tool,
        SubjectPath::Capability,
        SubjectPath::Action,
        SubjectPath::Runtime,
    ]
}

/// Project the evaluator input onto the declared paths. Fields that are not
/// declared stay empty on the wire.
#[must_use]
pub fn project(input: &EvalInput, paths: &[SubjectPath]) -> EvaluationSubject {
    let mut subject = EvaluationSubject::default();
    let mut args = Struct::default();
    let mut target = None;
    for path in paths {
        match path {
            SubjectPath::UserSubject => {
                subject.user_subject = input.user_subject.clone();
                subject.user_subject_attestation = if input.user_subject.is_empty() {
                    SUBJECT_ATTESTATION_NONE.to_owned()
                } else {
                    SUBJECT_ATTESTATION_CALLER.to_owned()
                };
            }
            SubjectPath::Tool => subject.tool = input.tool.clone().unwrap_or_default(),
            SubjectPath::Capability => {
                subject.capability = input.capability.clone().unwrap_or_default();
            }
            SubjectPath::Action => subject.action = input.action_id(),
            SubjectPath::Runtime | SubjectPath::RuntimePlatform => {
                subject.runtime = input.runtime.as_ref().map(|runtime| RuntimeIdentity {
                    platform: runtime.platform.clone(),
                    instance_id: runtime.instance_id.clone(),
                    agent_type: runtime.agent_type.clone().unwrap_or_default(),
                    attestation: runtime.attestation.as_str().to_owned(),
                });
            }
            SubjectPath::Arg(name) => {
                if let Some(value) = input.args.get(name).filter(|value| !value.is_null())
                    && let Ok(value) = json_to_proto_value(value)
                {
                    args.fields.insert(name.clone(), value);
                }
            }
            SubjectPath::TargetHost
            | SubjectPath::TargetMethod
            | SubjectPath::TargetPath
            | SubjectPath::TargetScheme => {
                if let Some(source) = &input.target {
                    let target = target.get_or_insert_with(RequestTarget::default);
                    match path {
                        SubjectPath::TargetHost => target.host = source.host.clone(),
                        SubjectPath::TargetMethod => target.method = source.method.clone(),
                        SubjectPath::TargetPath => target.path = source.path.clone(),
                        _ => target.scheme = source.scheme.clone(),
                    }
                }
            }
        }
    }
    if !args.fields.is_empty() {
        subject.args = Some(args);
    }
    subject.target = target;
    subject
}

/// Read one path from a projected subject as a string, for providers that
/// template requests from it. Composite argument values and absent fields
/// yield `None`.
#[must_use]
pub fn lookup_value(subject: &EvaluationSubject, path: &SubjectPath) -> Option<String> {
    use apf_proto::prost_types::value::Kind;
    let non_empty = |text: &str| (!text.is_empty()).then(|| text.to_owned());
    match path {
        SubjectPath::UserSubject => non_empty(&subject.user_subject),
        SubjectPath::Tool => non_empty(&subject.tool),
        SubjectPath::Capability => non_empty(&subject.capability),
        SubjectPath::Action => non_empty(&subject.action),
        SubjectPath::Runtime => subject
            .runtime
            .as_ref()
            .and_then(|runtime| non_empty(&runtime.instance_id)),
        SubjectPath::RuntimePlatform => subject
            .runtime
            .as_ref()
            .and_then(|runtime| non_empty(&runtime.platform)),
        SubjectPath::Arg(name) => match subject.args.as_ref()?.fields.get(name)?.kind.as_ref()? {
            Kind::StringValue(text) => non_empty(text),
            Kind::BoolValue(flag) => Some(flag.to_string()),
            Kind::NumberValue(number) => {
                if number.fract() == 0.0 && number.abs() < 9_007_199_254_740_992.0 {
                    Some(format!("{number:.0}"))
                } else {
                    Some(number.to_string())
                }
            }
            Kind::NullValue(_) | Kind::ListValue(_) | Kind::StructValue(_) => None,
        },
        SubjectPath::TargetHost => subject.target.as_ref().and_then(|t| non_empty(&t.host)),
        SubjectPath::TargetMethod => subject.target.as_ref().and_then(|t| non_empty(&t.method)),
        SubjectPath::TargetPath => subject.target.as_ref().and_then(|t| non_empty(&t.path)),
        SubjectPath::TargetScheme => subject.target.as_ref().and_then(|t| non_empty(&t.scheme)),
    }
}

#[cfg(test)]
mod tests {
    use apf_policy_eval::{RequestTarget as EvalTarget, RuntimeAttestation, RuntimeIdentity};
    use serde_json::json;

    use super::*;

    fn input() -> EvalInput {
        let mut args = serde_json::Map::new();
        args.insert("project".to_owned(), json!("nv/apf"));
        args.insert("iid".to_owned(), json!(214));
        args.insert("draft".to_owned(), json!(false));
        args.insert("labels".to_owned(), json!(["a", "b"]));
        args.insert("note".to_owned(), json!(null));
        let mut input = EvalInput::for_tool_call(
            Some("gitlab".to_owned()),
            Some("merge_request_merge".to_owned()),
            "user@corp.com".to_owned(),
            args,
        );
        input.target = Some(EvalTarget {
            host: "gitlab.example.com".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v4/projects/1/merge".to_owned(),
            scheme: "https".to_owned(),
        });
        input.runtime = Some(RuntimeIdentity {
            platform: "openshell".to_owned(),
            instance_id: "sb-7f2e".to_owned(),
            agent_type: None,
            attestation: RuntimeAttestation::OpenshellSupervisorJwt,
        });
        input
    }

    #[test]
    fn paths_parse_and_print() {
        for text in [
            "user_subject",
            "tool",
            "capability",
            "action",
            "runtime",
            "args.project",
            "target.host",
            "target.method",
            "target.path",
            "target.scheme",
        ] {
            let path: SubjectPath = text.parse().expect(text);
            assert_eq!(path.to_string(), text);
        }
        assert_eq!(
            "runtime.instance_id".parse::<SubjectPath>().expect("alias"),
            SubjectPath::Runtime
        );
        assert_eq!(
            "runtime.platform".parse::<SubjectPath>().expect("platform"),
            SubjectPath::RuntimePlatform
        );
        assert_eq!(SubjectPath::RuntimePlatform.to_string(), "runtime.platform");
        for bad in ["", "args.", "body_text", "args.has space", "target"] {
            assert!(bad.parse::<SubjectPath>().is_err(), "{bad}");
        }
        let parsed: Vec<SubjectPath> =
            serde_yaml::from_str("[action, args.project]").expect("yaml list");
        assert_eq!(
            parsed,
            vec![SubjectPath::Action, SubjectPath::Arg("project".to_owned())]
        );
    }

    #[test]
    fn default_projection_carries_identity_and_action_only() {
        let subject = project(&input(), &default_subject());
        assert_eq!(subject.user_subject, "user@corp.com");
        assert_eq!(subject.user_subject_attestation, SUBJECT_ATTESTATION_CALLER);
        assert_eq!(subject.tool, "gitlab");
        assert_eq!(subject.capability, "merge_request_merge");
        assert_eq!(subject.action, "gitlab::merge_request_merge");
        let runtime = subject.runtime.expect("runtime projected");
        assert_eq!(runtime.instance_id, "sb-7f2e");
        assert_eq!(runtime.attestation, "openshell-supervisor-jwt");
        assert!(subject.args.is_none(), "arguments are opt-in");
        assert!(subject.target.is_none(), "target is opt-in");
    }

    #[test]
    fn declared_arguments_and_target_fields_are_projected() {
        let subject = project(
            &input(),
            &[
                SubjectPath::Arg("project".to_owned()),
                SubjectPath::Arg("note".to_owned()),
                SubjectPath::Arg("missing".to_owned()),
                SubjectPath::TargetHost,
            ],
        );
        let args = subject.args.as_ref().expect("args projected");
        assert_eq!(
            args.fields.len(),
            1,
            "null and missing arguments are skipped"
        );
        assert_eq!(
            lookup_value(&subject, &SubjectPath::Arg("project".to_owned())).as_deref(),
            Some("nv/apf")
        );
        let target = subject.target.as_ref().expect("target projected");
        assert_eq!(target.host, "gitlab.example.com");
        assert!(
            target.method.is_empty(),
            "undeclared target fields stay empty"
        );
        assert!(subject.user_subject.is_empty());
        assert!(subject.user_subject_attestation.is_empty());
    }

    #[test]
    fn empty_subject_is_attested_as_none() {
        let mut anonymous = input();
        anonymous.user_subject.clear();
        let subject = project(&anonymous, &[SubjectPath::UserSubject]);
        assert_eq!(subject.user_subject_attestation, SUBJECT_ATTESTATION_NONE);
    }

    #[test]
    fn lookup_values_render_scalars_only() {
        let subject = project(
            &input(),
            &[
                SubjectPath::Arg("iid".to_owned()),
                SubjectPath::Arg("draft".to_owned()),
                SubjectPath::Arg("labels".to_owned()),
                SubjectPath::Runtime,
            ],
        );
        assert_eq!(
            lookup_value(&subject, &SubjectPath::Arg("iid".to_owned())).as_deref(),
            Some("214")
        );
        assert_eq!(
            lookup_value(&subject, &SubjectPath::Arg("draft".to_owned())).as_deref(),
            Some("false")
        );
        assert_eq!(
            lookup_value(&subject, &SubjectPath::Arg("labels".to_owned())),
            None
        );
        assert_eq!(
            lookup_value(&subject, &SubjectPath::Runtime).as_deref(),
            Some("sb-7f2e")
        );
        assert_eq!(
            lookup_value(&subject, &SubjectPath::RuntimePlatform).as_deref(),
            Some("openshell")
        );
        assert_eq!(lookup_value(&subject, &SubjectPath::Tool), None);
    }
}
