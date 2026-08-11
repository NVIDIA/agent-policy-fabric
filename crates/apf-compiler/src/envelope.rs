// SPDX-License-Identifier: Apache-2.0
//! Envelope conformance lint for bundle members.
//!
//! Checks that every kinded APF bundle member keeps a uniform envelope:
//! a non-empty `kind`, a `metadata.name` where the kind requires one, no
//! `metadata.namespace` where the kind forbids it, and an `apiVersion` matching
//! the group expected for that kind. The per-kind expectations live in one place
//! ([`EXPECTED`]) so envelope drift surfaces as a lint failure rather than
//! propagating silently into new fixtures.
//!
//! The apiVersion group is per area (`nvidia.agent-policy-fabric.<area>/v1alpha1`,
//! the package namespace with the area as the final segment): `Provider`,
//! `PolicyBundle`, `PolicyRule`, `PolicyAnnotator`, `PolicyEffect`, and
//! `PolicyFinding` share the `policy` group; `SandboxPolicy` carries its own.
//!
//! Kindless members (OpenShell-native `ProviderProfile` documents, which carry a
//! top-level `id` instead of an envelope) are not APF envelopes and are skipped.

/// Per-kind envelope expectations.
struct KindRule {
    /// The apiVersion group this kind currently authors.
    group: &'static str,
    /// Whether `metadata.name` must be present and non-empty.
    requires_name: bool,
    /// Whether `metadata.namespace` is forbidden.
    forbids_namespace: bool,
}

/// Policy-area group shared by the kinds whose proto package is
/// `nvidia.agent_policy_fabric.policy.v1alpha1`.
const POLICY_GROUP: &str = "nvidia.agent-policy-fabric.policy/v1alpha1";

/// Expected envelope per member kind, reflecting today's reality. New kinds
/// without an entry are rejected so fixtures cannot drift in unnoticed.
const EXPECTED: &[(&str, KindRule)] = &[
    (
        "Provider",
        KindRule {
            group: POLICY_GROUP,
            requires_name: true,
            forbids_namespace: true,
        },
    ),
    (
        "SandboxPolicy",
        KindRule {
            group: "nvidia.agent-policy-fabric.sandbox/v1alpha1",
            requires_name: true,
            forbids_namespace: true,
        },
    ),
    (
        "PolicyBundle",
        KindRule {
            group: POLICY_GROUP,
            requires_name: false,
            forbids_namespace: true,
        },
    ),
    (
        "PolicyRule",
        KindRule {
            group: POLICY_GROUP,
            requires_name: true,
            forbids_namespace: true,
        },
    ),
    (
        "PolicyAnnotator",
        KindRule {
            group: POLICY_GROUP,
            requires_name: true,
            forbids_namespace: true,
        },
    ),
    (
        "PolicyEffect",
        KindRule {
            group: POLICY_GROUP,
            requires_name: true,
            forbids_namespace: true,
        },
    ),
    (
        "PolicyFinding",
        KindRule {
            group: POLICY_GROUP,
            requires_name: true,
            forbids_namespace: true,
        },
    ),
];

/// A single envelope violation, naming the offending kind and the broken
/// invariant.
#[derive(Debug, PartialEq, Eq)]
pub struct EnvelopeViolation(pub String);

/// Check one bundle member's envelope. Members without a `kind` are treated as
/// non-envelope documents and pass. A `kind` with no [`EXPECTED`] entry fails.
pub fn check_member(doc: &serde_yaml::Value) -> Result<(), EnvelopeViolation> {
    let kind = if let Some(k) = doc.get("kind").and_then(serde_yaml::Value::as_str) {
        k
    } else {
        // A document that declares neither `kind` nor a native-profile `id`
        // is a malformed envelope; a native profile (top-level `id`) is not
        // an APF envelope and is out of scope.
        if doc.get("id").and_then(serde_yaml::Value::as_str).is_some() {
            return Ok(());
        }
        return Err(EnvelopeViolation("member has empty or missing kind".into()));
    };
    if kind.is_empty() {
        return Err(EnvelopeViolation("member has empty or missing kind".into()));
    }

    let rule = match EXPECTED.iter().find(|(k, _)| *k == kind) {
        Some((_, rule)) => rule,
        None => {
            return Err(EnvelopeViolation(format!(
                "kind {kind} has no expected-envelope entry; add one to record its apiVersion group"
            )));
        }
    };

    let api_version = doc
        .get("apiVersion")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default();
    if api_version != rule.group {
        return Err(EnvelopeViolation(format!(
            "kind {kind}: apiVersion {api_version:?} does not match expected group {:?}",
            rule.group
        )));
    }

    let metadata = doc.get("metadata");
    if rule.requires_name {
        let has_name = metadata
            .and_then(|m| m.get("name"))
            .and_then(serde_yaml::Value::as_str)
            .is_some_and(|n| !n.is_empty());
        if !has_name {
            return Err(EnvelopeViolation(format!(
                "kind {kind}: missing or empty metadata.name"
            )));
        }
    }
    if rule.forbids_namespace && metadata.and_then(|m| m.get("namespace")).is_some() {
        return Err(EnvelopeViolation(format!(
            "kind {kind}: metadata.namespace is forbidden"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_kind() {
        let doc: serde_yaml::Value =
            serde_yaml::from_str("apiVersion: x\nmetadata: { name: foo }\n").unwrap();
        assert!(check_member(&doc).is_err());
    }

    #[test]
    fn rejects_namespace() {
        let doc: serde_yaml::Value = serde_yaml::from_str(
            "apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1\nkind: Provider\nmetadata: { name: foo, namespace: bar }\n",
        )
        .unwrap();
        assert_eq!(
            check_member(&doc),
            Err(EnvelopeViolation(
                "kind Provider: metadata.namespace is forbidden".into()
            ))
        );
    }

    #[test]
    fn rejects_wrong_group() {
        let doc: serde_yaml::Value = serde_yaml::from_str(
            "apiVersion: nvidia.agent-policy-fabric.sandbox/v1alpha1\nkind: Provider\nmetadata: { name: foo }\n",
        )
        .unwrap();
        assert!(check_member(&doc).is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        let doc: serde_yaml::Value =
            serde_yaml::from_str("apiVersion: x\nkind: Mystery\nmetadata: { name: foo }\n")
                .unwrap();
        assert!(check_member(&doc).is_err());
    }

    #[test]
    fn requires_name_for_provider() {
        let doc: serde_yaml::Value = serde_yaml::from_str(
            "apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1\nkind: Provider\nmetadata: {}\n",
        )
        .unwrap();
        assert!(check_member(&doc).is_err());
    }
}
