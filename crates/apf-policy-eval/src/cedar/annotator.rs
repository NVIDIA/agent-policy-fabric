// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Annotation pre-processor for the Cedar evaluator.
//!
//! [`AnnotatorEngine`] compiles a list of [`PolicyAnnotatorDoc`]s at
//! construction time and, per request, derives annotation values from the
//! raw [`EvalInput`]. The results are injected into the Cedar context as the
//! `annotations` record so policies can condition on them — this covers the
//! string operations (regex, suffix, length, …) Cedar cannot express.
//!
//! Annotators are independent: each reads only the raw input and can never
//! see another annotator's output, so they run sequentially in load order
//! without ordering semantics. All patterns compile at construction — an
//! invalid rule is a load-time error, never an eval-time one.

use serde_json::{Map, Value};

use crate::{EvalError, EvalInput};

/// One `PolicyAnnotator` document as handed to the evaluator.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyAnnotatorDoc {
    pub name: String,
    pub annotations: Vec<AnnotationSpec>,
}

/// One annotation an annotator emits.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationSpec {
    /// Key under `context.annotations` in Cedar policies.
    pub name: String,
    pub output: AnnotationOutput,
    /// Rule combinator for `bool` output.
    pub set_true_if: SetTrueIf,
    /// Value selection for `string` output.
    pub set_value_from: SetValueFrom,
    pub rules: Vec<AnnotationRule>,
}

/// Type of the emitted annotation value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationOutput {
    Bool,
    String,
    Integer,
}

/// How a `bool` annotation combines its rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SetTrueIf {
    #[default]
    Any,
    All,
}

/// How a `string` annotation selects its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SetValueFrom {
    #[default]
    FirstMatch,
}

/// One match rule inside an annotation. The operand fields are op-specific;
/// the engine validates presence at construction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AnnotationRule {
    /// Field selector resolved against the raw input: `body_text`,
    /// `body_json.<json-pointer>`, `args.<name>`, `target.host`,
    /// `target.path`, `target.method`, or `user_subject`.
    pub field: String,
    pub op: AnnotationOp,
    /// Regex for `regex_match`.
    pub pattern: Option<String>,
    /// Comparison operand for `equals`; also the label a matching rule emits
    /// under `string` output.
    pub value: Option<String>,
    /// Operand for `endswith`.
    pub suffix: Option<String>,
    /// Operand for `startswith`.
    pub prefix: Option<String>,
    /// Operand for `contains`.
    pub substring: Option<String>,
    /// Operand for `gte`/`lte`.
    pub threshold: Option<i64>,
}

/// Match operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnnotationOp {
    #[default]
    RegexMatch,
    Equals,
    EndsWith,
    StartsWith,
    Contains,
    Length,
    Gte,
    Lte,
    Passthrough,
}

impl AnnotationOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::RegexMatch => "regex_match",
            Self::Equals => "equals",
            Self::EndsWith => "endswith",
            Self::StartsWith => "startswith",
            Self::Contains => "contains",
            Self::Length => "length",
            Self::Gte => "gte",
            Self::Lte => "lte",
            Self::Passthrough => "passthrough",
        }
    }
}

/// Runs every compiled annotator against a request's raw input. Immutable
/// after construction; safe to share across threads.
pub struct AnnotatorEngine {
    annotations: Vec<CompiledAnnotation>,
}

impl std::fmt::Debug for AnnotatorEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnotatorEngine")
            .field(
                "annotations",
                &self.annotations.iter().map(|a| &a.name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl AnnotatorEngine {
    /// Compile every annotator's rules. Invalid patterns, missing operands,
    /// output/op mismatches, and duplicate annotation keys are load-time
    /// errors.
    pub fn from_docs(docs: &[PolicyAnnotatorDoc]) -> Result<Self, EvalError> {
        let mut annotations = Vec::new();
        let mut owners: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for doc in docs {
            for spec in &doc.annotations {
                if let Some(prev) = owners.insert(spec.name.clone(), doc.name.clone()) {
                    return Err(EvalError::Engine(format!(
                        "annotator '{}': duplicate annotation key '{}' (already emitted by annotator '{prev}')",
                        doc.name, spec.name
                    )));
                }
                annotations.push(compile_annotation(&doc.name, spec)?);
            }
        }
        Ok(Self { annotations })
    }

    /// Evaluate every annotation against `input`. Returns the `annotations`
    /// record for the Cedar context: bool annotations are always present,
    /// string and integer annotations only when a rule produced a value.
    #[must_use]
    pub fn run(&self, input: &EvalInput) -> Map<String, Value> {
        let mut out = Map::new();
        for ann in &self.annotations {
            match ann.output {
                AnnotationOutput::Bool => {
                    let hit = match ann.set_true_if {
                        SetTrueIf::Any => ann.rules.iter().any(|r| r.matches(input)),
                        SetTrueIf::All => ann.rules.iter().all(|r| r.matches(input)),
                    };
                    out.insert(ann.name.clone(), Value::Bool(hit));
                }
                AnnotationOutput::String => {
                    if let Some(rule) = ann.rules.iter().find(|r| r.matches(input))
                        && let Some(label) = &rule.label
                    {
                        out.insert(ann.name.clone(), Value::String(label.clone()));
                    }
                }
                AnnotationOutput::Integer => {
                    if let Some(n) = ann.rules.iter().find_map(|r| r.integer_value(input)) {
                        out.insert(ann.name.clone(), Value::from(n));
                    }
                }
            }
        }
        out
    }
}

struct CompiledAnnotation {
    name: String,
    output: AnnotationOutput,
    set_true_if: SetTrueIf,
    rules: Vec<CompiledMatch>,
}

struct CompiledMatch {
    field: FieldSelector,
    matcher: Matcher,
    /// Label emitted on match under `string` output.
    label: Option<String>,
}

enum Matcher {
    Regex(regex::Regex),
    Equals(String),
    EndsWith(String),
    StartsWith(String),
    Contains(String),
    Gte(i64),
    Lte(i64),
    Length,
    Passthrough,
}

impl CompiledMatch {
    /// Predicate evaluation. An unresolvable field never matches.
    fn matches(&self, input: &EvalInput) -> bool {
        let Some(resolved) = self.field.resolve(input) else {
            return false;
        };
        match &self.matcher {
            Matcher::Regex(re) => resolved.as_str().is_some_and(|s| re.is_match(s)),
            Matcher::Equals(v) => resolved.as_str() == Some(v.as_str()),
            Matcher::EndsWith(v) => resolved.as_str().is_some_and(|s| s.ends_with(v)),
            Matcher::StartsWith(v) => resolved.as_str().is_some_and(|s| s.starts_with(v)),
            Matcher::Contains(v) => resolved.as_str().is_some_and(|s| s.contains(v)),
            Matcher::Gte(t) => resolved.as_i64().is_some_and(|n| n >= *t),
            Matcher::Lte(t) => resolved.as_i64().is_some_and(|n| n <= *t),
            // Producer ops carry no predicate; construction rejects them
            // outside integer output.
            Matcher::Length | Matcher::Passthrough => false,
        }
    }

    /// Producer evaluation for `integer` output. `None` when the field is
    /// unresolvable or not representable as an integer.
    fn integer_value(&self, input: &EvalInput) -> Option<i64> {
        let resolved = self.field.resolve(input)?;
        match &self.matcher {
            Matcher::Length => resolved
                .as_str()
                .map(|s| i64::try_from(s.chars().count()).unwrap_or(i64::MAX)),
            Matcher::Passthrough => resolved.as_i64(),
            _ => None,
        }
    }
}

/// Where a rule's field resolves from in the raw input.
enum FieldSelector {
    BodyText,
    /// RFC 6901 pointer into `body_json`.
    BodyJson(String),
    Arg(String),
    TargetHost,
    TargetPath,
    TargetMethod,
    UserSubject,
}

impl FieldSelector {
    fn parse(field: &str) -> Result<Self, String> {
        match field {
            "body_text" => return Ok(Self::BodyText),
            "body_json" => return Ok(Self::BodyJson(String::new())),
            "target.host" => return Ok(Self::TargetHost),
            "target.path" => return Ok(Self::TargetPath),
            "target.method" => return Ok(Self::TargetMethod),
            "user_subject" => return Ok(Self::UserSubject),
            _ => {}
        }
        if let Some(rest) = field.strip_prefix("body_json.") {
            // Accept an RFC 6901 pointer verbatim (`body_json./a/b`) or a
            // dotted path (`body_json.a.b`) converted to one.
            let pointer = if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{}", rest.replace('.', "/"))
            };
            return Ok(Self::BodyJson(pointer));
        }
        if let Some(name) = field.strip_prefix("args.")
            && !name.is_empty()
        {
            return Ok(Self::Arg(name.to_string()));
        }
        Err(format!("unknown field selector '{field}'"))
    }

    fn resolve<'a>(&self, input: &'a EvalInput) -> Option<Resolved<'a>> {
        match self {
            Self::BodyText => Some(Resolved::Str(&input.body_text)),
            Self::BodyJson(pointer) => input
                .body_json
                .as_ref()
                .and_then(|body| body.pointer(pointer))
                .map(Resolved::Json),
            Self::Arg(name) => input.args.get(name).map(Resolved::Json),
            Self::TargetHost => input.target.as_ref().map(|t| Resolved::Str(&t.host)),
            Self::TargetPath => input.target.as_ref().map(|t| Resolved::Str(&t.path)),
            Self::TargetMethod => input.target.as_ref().map(|t| Resolved::Str(&t.method)),
            Self::UserSubject => Some(Resolved::Str(&input.user_subject)),
        }
    }
}

/// A resolved field value: a borrowed string or a JSON node.
enum Resolved<'a> {
    Str(&'a str),
    Json(&'a Value),
}

impl Resolved<'_> {
    fn as_str(&self) -> Option<&str> {
        match self {
            Resolved::Str(s) => Some(s),
            Resolved::Json(Value::String(s)) => Some(s),
            Resolved::Json(_) => None,
        }
    }

    /// Integer view: JSON numbers directly, strings via parse.
    fn as_i64(&self) -> Option<i64> {
        match self {
            Resolved::Json(Value::Number(n)) => n.as_i64(),
            other => other.as_str().and_then(|s| s.trim().parse().ok()),
        }
    }
}

fn compile_annotation(
    annotator: &str,
    spec: &AnnotationSpec,
) -> Result<CompiledAnnotation, EvalError> {
    let load_err = |cause: String| {
        EvalError::Engine(format!(
            "annotator '{annotator}' annotation '{}': {cause}",
            spec.name
        ))
    };

    if spec.rules.is_empty() {
        return Err(load_err("no rules".to_string()));
    }

    let rules = spec
        .rules
        .iter()
        .map(|rule| compile_match(spec.output, rule).map_err(&load_err))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompiledAnnotation {
        name: spec.name.clone(),
        output: spec.output,
        set_true_if: spec.set_true_if,
        rules,
    })
}

fn compile_match(output: AnnotationOutput, rule: &AnnotationRule) -> Result<CompiledMatch, String> {
    let field = FieldSelector::parse(&rule.field)?;

    let operand = |value: &Option<String>, name: &str| {
        value
            .clone()
            .ok_or_else(|| format!("op '{}' requires '{name}'", rule.op.as_str()))
    };
    let threshold = || {
        rule.threshold
            .ok_or_else(|| format!("op '{}' requires 'threshold'", rule.op.as_str()))
    };

    let matcher = match rule.op {
        AnnotationOp::RegexMatch => {
            let pattern = operand(&rule.pattern, "pattern")?;
            let re = regex::Regex::new(&pattern).map_err(|e| format!("invalid pattern: {e}"))?;
            Matcher::Regex(re)
        }
        AnnotationOp::Equals => Matcher::Equals(operand(&rule.value, "value")?),
        AnnotationOp::EndsWith => Matcher::EndsWith(operand(&rule.suffix, "suffix")?),
        AnnotationOp::StartsWith => Matcher::StartsWith(operand(&rule.prefix, "prefix")?),
        AnnotationOp::Contains => Matcher::Contains(operand(&rule.substring, "substring")?),
        AnnotationOp::Gte => Matcher::Gte(threshold()?),
        AnnotationOp::Lte => Matcher::Lte(threshold()?),
        AnnotationOp::Length => Matcher::Length,
        AnnotationOp::Passthrough => Matcher::Passthrough,
    };

    let is_producer = matches!(matcher, Matcher::Length | Matcher::Passthrough);
    match output {
        AnnotationOutput::Integer if !is_producer => {
            return Err(format!(
                "op '{}' not valid for integer output (expected length or passthrough)",
                rule.op.as_str()
            ));
        }
        AnnotationOutput::Bool | AnnotationOutput::String if is_producer => {
            return Err(format!(
                "op '{}' only valid for integer output",
                rule.op.as_str()
            ));
        }
        _ => {}
    }
    if output == AnnotationOutput::String && rule.value.is_none() {
        return Err("string output requires 'value' on every rule".to_string());
    }

    Ok(CompiledMatch {
        field,
        matcher,
        label: rule.value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestTarget;

    fn doc(annotations: Vec<AnnotationSpec>) -> PolicyAnnotatorDoc {
        PolicyAnnotatorDoc {
            name: "test-annotator".to_string(),
            annotations,
        }
    }

    fn bool_spec(name: &str, set_true_if: SetTrueIf, rules: Vec<AnnotationRule>) -> AnnotationSpec {
        AnnotationSpec {
            name: name.to_string(),
            output: AnnotationOutput::Bool,
            set_true_if,
            set_value_from: SetValueFrom::FirstMatch,
            rules,
        }
    }

    fn engine(annotations: Vec<AnnotationSpec>) -> AnnotatorEngine {
        AnnotatorEngine::from_docs(&[doc(annotations)]).expect("engine should build")
    }

    fn input_with_body(body: &str) -> EvalInput {
        EvalInput {
            body_text: body.to_string(),
            user_subject: "user@corp.com".to_string(),
            ..EvalInput::default()
        }
    }

    fn rule(field: &str, op: AnnotationOp) -> AnnotationRule {
        AnnotationRule {
            field: field.to_string(),
            op,
            ..AnnotationRule::default()
        }
    }

    #[test]
    fn regex_match_on_body_text() {
        let mut r = rule("body_text", AnnotationOp::RegexMatch);
        r.pattern = Some(r"AKIA[0-9A-Z]{16}".to_string());
        let eng = engine(vec![bool_spec("secret_detected", SetTrueIf::Any, vec![r])]);

        let hit = eng.run(&input_with_body("key=AKIA0123456789ABCDEF"));
        assert_eq!(hit["secret_detected"], Value::Bool(true));
        let miss = eng.run(&input_with_body("no secrets here"));
        assert_eq!(miss["secret_detected"], Value::Bool(false));
    }

    #[test]
    fn equals_on_arg() {
        let mut r = rule("args.folder", AnnotationOp::Equals);
        r.value = Some("archive".to_string());
        let eng = engine(vec![bool_spec("archive_access", SetTrueIf::Any, vec![r])]);

        let mut input = input_with_body("");
        input
            .args
            .insert("folder".to_string(), Value::String("archive".to_string()));
        assert_eq!(eng.run(&input)["archive_access"], Value::Bool(true));

        input
            .args
            .insert("folder".to_string(), Value::String("inbox".to_string()));
        assert_eq!(eng.run(&input)["archive_access"], Value::Bool(false));
    }

    #[test]
    fn endswith_startswith_contains_on_user_and_target() {
        let mut ends = rule("user_subject", AnnotationOp::EndsWith);
        ends.suffix = Some("@corp.com".to_string());
        let mut starts = rule("target.path", AnnotationOp::StartsWith);
        starts.prefix = Some("/v1/".to_string());
        let mut contains = rule("target.host", AnnotationOp::Contains);
        contains.substring = Some("example".to_string());
        let eng = engine(vec![bool_spec(
            "all_checks",
            SetTrueIf::All,
            vec![ends, starts, contains],
        )]);

        let mut input = input_with_body("");
        input.target = Some(RequestTarget {
            host: "api.example.com".to_string(),
            method: "GET".to_string(),
            path: "/v1/messages".to_string(),
            scheme: "https".to_string(),
        });
        assert_eq!(eng.run(&input)["all_checks"], Value::Bool(true));

        input.target.as_mut().unwrap().path = "/v2/messages".to_string();
        assert_eq!(eng.run(&input)["all_checks"], Value::Bool(false));
    }

    #[test]
    fn any_matches_when_one_rule_hits() {
        let mut a = rule("args.folder", AnnotationOp::Equals);
        a.value = Some("archive".to_string());
        let mut b = rule("user_subject", AnnotationOp::EndsWith);
        b.suffix = Some("@corp.com".to_string());
        let eng = engine(vec![bool_spec("flagged", SetTrueIf::Any, vec![a, b])]);

        // Only the user_subject rule matches.
        assert_eq!(eng.run(&input_with_body(""))["flagged"], Value::Bool(true));
    }

    #[test]
    fn gte_lte_on_numeric_fields() {
        let mut gte = rule("args.limit", AnnotationOp::Gte);
        gte.threshold = Some(10);
        let mut lte = rule("args.limit", AnnotationOp::Lte);
        lte.threshold = Some(100);
        let eng = engine(vec![
            bool_spec("at_least_ten", SetTrueIf::Any, vec![gte]),
            bool_spec("at_most_hundred", SetTrueIf::Any, vec![lte]),
        ]);

        let mut input = input_with_body("");
        // Numeric JSON value.
        input.args.insert("limit".to_string(), Value::from(50));
        let out = eng.run(&input);
        assert_eq!(out["at_least_ten"], Value::Bool(true));
        assert_eq!(out["at_most_hundred"], Value::Bool(true));

        // String value parsed as an integer.
        input
            .args
            .insert("limit".to_string(), Value::String("5".to_string()));
        let out = eng.run(&input);
        assert_eq!(out["at_least_ten"], Value::Bool(false));
        assert_eq!(out["at_most_hundred"], Value::Bool(true));

        // Non-numeric value never matches.
        input
            .args
            .insert("limit".to_string(), Value::String("many".to_string()));
        let out = eng.run(&input);
        assert_eq!(out["at_least_ten"], Value::Bool(false));
        assert_eq!(out["at_most_hundred"], Value::Bool(false));
    }

    #[test]
    fn length_and_passthrough_integer_output() {
        let specs = vec![
            AnnotationSpec {
                name: "subject_len".to_string(),
                output: AnnotationOutput::Integer,
                set_true_if: SetTrueIf::default(),
                set_value_from: SetValueFrom::default(),
                rules: vec![rule("args.subject", AnnotationOp::Length)],
            },
            AnnotationSpec {
                name: "limit_value".to_string(),
                output: AnnotationOutput::Integer,
                set_true_if: SetTrueIf::default(),
                set_value_from: SetValueFrom::default(),
                rules: vec![rule("args.limit", AnnotationOp::Passthrough)],
            },
        ];
        let eng = engine(specs);

        let mut input = input_with_body("");
        input
            .args
            .insert("subject".to_string(), Value::String("héllo".to_string()));
        input.args.insert("limit".to_string(), Value::from(25));
        let out = eng.run(&input);
        assert_eq!(out["subject_len"], Value::from(5));
        assert_eq!(out["limit_value"], Value::from(25));

        // Unresolvable fields leave the annotations absent.
        let out = eng.run(&input_with_body(""));
        assert!(!out.contains_key("subject_len"));
        assert!(!out.contains_key("limit_value"));
    }

    #[test]
    fn string_first_match_takes_first_matching_rule() {
        let mut high = rule("body_text", AnnotationOp::Contains);
        high.substring = Some("password".to_string());
        high.value = Some("credential".to_string());
        let mut low = rule("body_text", AnnotationOp::Contains);
        low.substring = Some("email".to_string());
        low.value = Some("pii".to_string());
        let eng = engine(vec![AnnotationSpec {
            name: "content_class".to_string(),
            output: AnnotationOutput::String,
            set_true_if: SetTrueIf::default(),
            set_value_from: SetValueFrom::FirstMatch,
            rules: vec![high, low],
        }]);

        let out = eng.run(&input_with_body("password and email inside"));
        assert_eq!(
            out["content_class"],
            Value::String("credential".to_string())
        );

        let out = eng.run(&input_with_body("just an email"));
        assert_eq!(out["content_class"], Value::String("pii".to_string()));

        // No match → annotation absent.
        let out = eng.run(&input_with_body("clean"));
        assert!(!out.contains_key("content_class"));
    }

    #[test]
    fn json_pointer_into_body_json() {
        let mut dotted = rule("body_json.message.text", AnnotationOp::Contains);
        dotted.substring = Some("secret".to_string());
        let mut pointer = rule("body_json./message/count", AnnotationOp::Gte);
        pointer.threshold = Some(3);
        let eng = engine(vec![
            bool_spec("text_flag", SetTrueIf::Any, vec![dotted]),
            bool_spec("count_flag", SetTrueIf::Any, vec![pointer]),
        ]);

        let mut input = input_with_body("");
        input.body_json = Some(serde_json::json!({
            "message": { "text": "a secret note", "count": 4 }
        }));
        let out = eng.run(&input);
        assert_eq!(out["text_flag"], Value::Bool(true));
        assert_eq!(out["count_flag"], Value::Bool(true));
    }

    #[test]
    fn missing_field_never_matches() {
        let mut missing_arg = rule("args.absent", AnnotationOp::Equals);
        missing_arg.value = Some("x".to_string());
        let mut missing_target = rule("target.host", AnnotationOp::Contains);
        missing_target.substring = Some("x".to_string());
        let mut missing_json = rule("body_json.some.path", AnnotationOp::Contains);
        missing_json.substring = Some("x".to_string());
        let eng = engine(vec![
            bool_spec("any_hit", SetTrueIf::Any, vec![missing_arg.clone()]),
            bool_spec(
                "all_hit",
                SetTrueIf::All,
                vec![missing_arg, missing_target, missing_json],
            ),
        ]);

        let out = eng.run(&input_with_body(""));
        assert_eq!(out["any_hit"], Value::Bool(false));
        assert_eq!(out["all_hit"], Value::Bool(false));
    }

    #[test]
    fn invalid_regex_is_load_error() {
        let mut r = rule("body_text", AnnotationOp::RegexMatch);
        r.pattern = Some("(unclosed".to_string());
        let err =
            AnnotatorEngine::from_docs(&[doc(vec![bool_spec("bad", SetTrueIf::Any, vec![r])])])
                .expect_err("must fail");
        assert!(err.to_string().contains("invalid pattern"), "got: {err}");
    }

    #[test]
    fn missing_operand_is_load_error() {
        let r = rule("body_text", AnnotationOp::EndsWith);
        let err =
            AnnotatorEngine::from_docs(&[doc(vec![bool_spec("bad", SetTrueIf::Any, vec![r])])])
                .expect_err("must fail");
        assert!(err.to_string().contains("requires 'suffix'"), "got: {err}");
    }

    #[test]
    fn unknown_field_selector_is_load_error() {
        let mut r = rule("envelope.sender", AnnotationOp::Contains);
        r.substring = Some("x".to_string());
        let err =
            AnnotatorEngine::from_docs(&[doc(vec![bool_spec("bad", SetTrueIf::Any, vec![r])])])
                .expect_err("must fail");
        assert!(
            err.to_string().contains("unknown field selector"),
            "got: {err}"
        );
    }

    #[test]
    fn producer_op_under_bool_output_is_load_error() {
        let r = rule("args.subject", AnnotationOp::Length);
        let err =
            AnnotatorEngine::from_docs(&[doc(vec![bool_spec("bad", SetTrueIf::Any, vec![r])])])
                .expect_err("must fail");
        assert!(
            err.to_string().contains("only valid for integer output"),
            "got: {err}"
        );
    }

    #[test]
    fn duplicate_annotation_key_across_annotators_is_load_error() {
        let mut r = rule("body_text", AnnotationOp::Contains);
        r.substring = Some("x".to_string());
        let spec = bool_spec("flag", SetTrueIf::Any, vec![r]);
        let a = PolicyAnnotatorDoc {
            name: "first".to_string(),
            annotations: vec![spec.clone()],
        };
        let b = PolicyAnnotatorDoc {
            name: "second".to_string(),
            annotations: vec![spec],
        };
        let err = AnnotatorEngine::from_docs(&[a, b]).expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate annotation key 'flag'"),
            "got: {msg}"
        );
        assert!(
            msg.contains("first") && msg.contains("second"),
            "got: {msg}"
        );
    }

    #[test]
    fn zero_annotators_yield_empty_record() {
        let eng = AnnotatorEngine::from_docs(&[]).expect("empty engine builds");
        assert!(eng.run(&input_with_body("anything")).is_empty());
    }
}
