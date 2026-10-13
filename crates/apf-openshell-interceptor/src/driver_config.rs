// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Admission of caller-supplied compute-driver config (harness mounts).
//!
//! OpenShell lets a caller attach a volume by putting a driver-keyed
//! `driver_config` envelope on a `CreateSandbox` / `CreateSandboxTemplate`
//! request (the gateway requires `allow_driver_config = true` for this to
//! reach a driver at all). Within OpenShell's own guards any signed-in caller
//! could then attach any attachable volume, mounted any way — this module
//! closes that gap for APF by evaluating the request's driver config against a
//! `DriverConfigPolicy` carried in the **signed** `SandboxPolicy`.
//!
//! The decision is deny-by-default and has the properties a governance rule
//! needs to be safe:
//!   1. no rule in the signed bundle ⇒ any non-empty driver config is denied;
//!   2. the admitting role is taken only from the gateway-authenticated
//!      principal, never from a request field;
//!   3. a template-based create that carries driver config is refused (a
//!      template's driver config cannot be checked before it is resolved);
//!   4. mounts must match an allowed shape exactly — exact target, required
//!      read-only, a mount-count cap, a source prefix, and no extra keys;
//!   7. the request must carry exactly one driver key, and it must be the
//!      gateway's configured compute driver.
//!
//! (Properties 5 "every RPC" and 6 "audited" are the caller's responsibility:
//! the interceptor binds both `CreateSandbox` and `CreateSandboxTemplate` and
//! records every decision to the audit trail.)

use apf_proto::ir::{DriverConfigAllow, DriverConfigPolicy};
use prost::Message;
use serde_json::Value as JsonValue;

/// Decode the signed driver-config rule carried in the provenance JWT
/// `apf/driver-config` claim (hex-encoded `DriverConfigPolicy` protobuf).
/// Returns `None` when the claim is absent or unparsable — which the engine
/// treats as deny-by-default for any present driver config.
#[must_use]
pub fn decode_rule(claim: Option<&str>) -> Option<DriverConfigPolicy> {
    let bytes = hex::decode(claim?).ok()?;
    DriverConfigPolicy::decode(bytes.as_slice()).ok()
}

/// The outcome of a driver-config admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the driver config is admitted.
    pub allowed: bool,
    /// Stable code for the audit record and deny log.
    pub reason_code: &'static str,
    /// Human-readable detail for the deny response.
    pub detail: String,
}

impl Decision {
    fn allow(reason_code: &'static str) -> Self {
        Self {
            allowed: true,
            reason_code,
            detail: String::new(),
        }
    }

    fn deny(reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason_code,
            detail: detail.into(),
        }
    }
}

/// Whether a decoded `driver_config` envelope carries any configuration.
///
/// The envelope is a driver-keyed object, e.g. `{"podman": {"mounts": […]}}`.
/// `Null`, a non-object, or an object with no keys all mean "no driver config".
#[must_use]
pub fn is_present(driver_config: &JsonValue) -> bool {
    driver_config
        .as_object()
        .is_some_and(|m| m.values().any(|v| !is_empty_value(v)))
}

fn is_empty_value(v: &JsonValue) -> bool {
    match v {
        JsonValue::Null => true,
        JsonValue::Object(m) => m.is_empty(),
        _ => false,
    }
}

/// Evaluate a request's `driver_config` against the signed policy's allowlist.
///
/// * `rule` — the `DriverConfigPolicy` from the signed `SandboxPolicy`, if any.
/// * `driver_config` — the request's decoded driver-config envelope (driver-keyed).
/// * `is_template_based` — whether the create resolves a workload template.
/// * `principal_roles` — roles the **gateway** authenticated for the caller.
/// * `gateway_driver` — the gateway's configured compute driver (e.g. "podman").
#[must_use]
pub fn evaluate(
    rule: Option<&DriverConfigPolicy>,
    driver_config: &JsonValue,
    is_template_based: bool,
    principal_roles: &[String],
    gateway_driver: &str,
) -> Decision {
    // Nothing to govern inline. A template-based create is still refused when
    // an active rule denies templates, because the resolved template could
    // carry driver config the interceptor never sees here. With no rule there
    // is nothing to deny — the template itself is governed where it is created.
    if !is_present(driver_config) {
        if is_template_based && rule.is_some_and(|r| r.deny_templates) {
            return Decision::deny(
                "driver_config.denied.template",
                "template-based create cannot be admitted under a driver-config rule: a \
                 template's driver config cannot be verified before it is resolved",
            );
        }
        return Decision::allow("driver_config.absent");
    }

    // (1) Deny-by-default: present driver config with no allowlist is refused.
    let Some(rule) = rule.filter(|r| !r.allowed.is_empty()) else {
        return Decision::deny(
            "driver_config.denied.no_rule",
            "driver config is present but the signed policy carries no driver-config allowlist",
        );
    };

    // (3) A template-based create is refused before inspecting the inline config.
    if is_template_based && rule.deny_templates {
        return Decision::deny(
            "driver_config.denied.template",
            "template-based create carrying driver config is refused",
        );
    }

    // (7) Exactly one driver key, and it must be the gateway's own driver.
    let envelope = driver_config
        .as_object()
        .expect("is_present guarantees an object");
    let driver_keys: Vec<&String> = envelope
        .iter()
        .filter(|(_, v)| !is_empty_value(v))
        .map(|(k, _)| k)
        .collect();
    if driver_keys.len() != 1 {
        return Decision::deny(
            "driver_config.denied.multiple_drivers",
            format!(
                "driver config must carry exactly one driver key, found {}",
                driver_keys.len()
            ),
        );
    }
    let driver = driver_keys[0].as_str();
    if driver != gateway_driver {
        return Decision::deny(
            "driver_config.denied.wrong_driver",
            format!(
                "driver config uses driver {driver:?} but the gateway's compute driver is \
                 {gateway_driver:?}"
            ),
        );
    }

    let inner = &envelope[driver];

    // Evaluate against each allowed entry whose driver and role match; admit on
    // the first full match, otherwise report why the last candidate failed.
    let mut last_detail: Option<String> = None;
    for allow in &rule.allowed {
        if !allow.drivers.iter().any(|d| d == driver) {
            continue;
        }
        // (2) Role comes only from the gateway-authenticated principal.
        if !principal_roles.iter().any(|r| r == &allow.require_role) {
            last_detail = Some(format!(
                "caller lacks the required role {:?}",
                allow.require_role
            ));
            continue;
        }
        match match_entry(allow, inner) {
            Ok(()) => return Decision::allow("driver_config.allowed"),
            Err(detail) => last_detail = Some(detail),
        }
    }

    Decision::deny(
        "driver_config.denied.no_match",
        last_detail.unwrap_or_else(|| "driver config matched no allowed entry".to_string()),
    )
}

/// (4) Exact-match the inner driver block against one allowed entry.
///
/// The inner block may carry only a `mounts` array; every mount must match one
/// of the entry's mount shapes exactly and carry no key beyond the four we map.
fn match_entry(allow: &DriverConfigAllow, inner: &JsonValue) -> Result<(), String> {
    let obj = inner
        .as_object()
        .ok_or_else(|| "driver block is not an object".to_string())?;

    // No keys beyond `mounts`: anything we cannot map is a denial, not an ignore.
    for key in obj.keys() {
        if key != "mounts" {
            return Err(format!("driver block carries an unmappable key {key:?}"));
        }
    }

    let mounts = obj
        .get("mounts")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "driver block has no mounts array".to_string())?;

    if mounts.is_empty() {
        return Err("driver block declares no mounts".to_string());
    }
    if mounts.len() as u64 > u64::from(allow.max_mounts) {
        return Err(format!(
            "driver config declares {} mounts, the allowed maximum is {}",
            mounts.len(),
            allow.max_mounts
        ));
    }

    for mount in mounts {
        if !allow.mounts.iter().any(|shape| mount_matches(shape, mount)) {
            return Err(format!("mount {mount} matches no allowed mount shape"));
        }
    }
    Ok(())
}

/// Whether one request mount matches an allowed mount shape exactly.
fn mount_matches(shape: &apf_proto::ir::DriverConfigMount, mount: &JsonValue) -> bool {
    let Some(obj) = mount.as_object() else {
        return false;
    };
    // (4) No extra keys: a mount may carry only the four fields we map.
    const ALLOWED_KEYS: [&str; 4] = ["type", "source", "target", "read_only"];
    if obj.keys().any(|k| !ALLOWED_KEYS.contains(&k.as_str())) {
        return false;
    }

    let typ = obj.get("type").and_then(JsonValue::as_str).unwrap_or("");
    let source = obj.get("source").and_then(JsonValue::as_str).unwrap_or("");
    let target = obj.get("target").and_then(JsonValue::as_str).unwrap_or("");
    let read_only = obj
        .get("read_only")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);

    typ == shape.r#type
        && target == shape.target
        && !shape.source_prefix.is_empty()
        && source.starts_with(&shape.source_prefix)
        && (!shape.read_only || read_only)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_proto::ir::DriverConfigMount;
    use serde_json::json;

    fn harness_rule() -> DriverConfigPolicy {
        DriverConfigPolicy {
            deny_templates: true,
            allowed: vec![DriverConfigAllow {
                require_role: "openshell-admin".into(),
                drivers: vec!["podman".into(), "docker".into()],
                max_mounts: 1,
                mounts: vec![DriverConfigMount {
                    r#type: "volume".into(),
                    source_prefix: "saw-harness-".into(),
                    target: "/sandbox/harness".into(),
                    read_only: true,
                }],
            }],
        }
    }

    fn admin() -> Vec<String> {
        vec!["openshell-admin".into()]
    }

    fn good_config() -> JsonValue {
        json!({"podman": {"mounts": [
            {"type": "volume", "source": "saw-harness-42", "target": "/sandbox/harness", "read_only": true}
        ]}})
    }

    #[test]
    fn absent_driver_config_is_allowed() {
        let d = evaluate(
            Some(&harness_rule()),
            &JsonValue::Null,
            false,
            &admin(),
            "podman",
        );
        assert!(d.allowed, "{d:?}");
        assert_eq!(d.reason_code, "driver_config.absent");
    }

    #[test]
    fn empty_envelope_is_allowed() {
        let cfg = json!({"podman": {}});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(d.allowed, "{d:?}");
    }

    // (1) deny-by-default
    #[test]
    fn present_config_without_rule_is_denied() {
        let d = evaluate(None, &good_config(), false, &admin(), "podman");
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.no_rule");
    }

    #[test]
    fn present_config_with_empty_allowlist_is_denied() {
        let rule = DriverConfigPolicy {
            deny_templates: true,
            allowed: vec![],
        };
        let d = evaluate(Some(&rule), &good_config(), false, &admin(), "podman");
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.no_rule");
    }

    // happy path
    #[test]
    fn exact_harness_mount_is_allowed() {
        let d = evaluate(
            Some(&harness_rule()),
            &good_config(),
            false,
            &admin(),
            "podman",
        );
        assert!(d.allowed, "{d:?}");
        assert_eq!(d.reason_code, "driver_config.allowed");
    }

    // (2) identity from the gateway only
    #[test]
    fn missing_required_role_is_denied() {
        let roles = vec!["developer".into()];
        let d = evaluate(
            Some(&harness_rule()),
            &good_config(),
            false,
            &roles,
            "podman",
        );
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.no_match");
    }

    // (3) refuse templates — inline config present
    #[test]
    fn template_based_create_with_config_is_denied() {
        let d = evaluate(
            Some(&harness_rule()),
            &good_config(),
            true,
            &admin(),
            "podman",
        );
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.template");
    }

    // (3) refuse templates — even with no inline config, a deny_templates rule blocks
    #[test]
    fn template_based_create_without_config_is_denied_when_templates_denied() {
        let d = evaluate(
            Some(&harness_rule()),
            &JsonValue::Null,
            true,
            &admin(),
            "podman",
        );
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.template");
    }

    #[test]
    fn template_based_create_allowed_when_rule_permits_templates() {
        let mut rule = harness_rule();
        rule.deny_templates = false;
        // No inline config and templates permitted ⇒ nothing to govern here.
        let d = evaluate(Some(&rule), &JsonValue::Null, true, &admin(), "podman");
        assert!(d.allowed, "{d:?}");
    }

    // (7) only the gateway's driver
    #[test]
    fn driver_mismatch_with_gateway_is_denied() {
        // Rule lists docker, but the gateway runs podman.
        let d = evaluate(
            Some(&harness_rule()),
            &good_config(),
            false,
            &admin(),
            "docker",
        );
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.wrong_driver");
    }

    #[test]
    fn multiple_driver_keys_are_denied() {
        let cfg = json!({
            "podman": {"mounts": [{"type": "volume", "source": "saw-harness-1", "target": "/sandbox/harness", "read_only": true}]},
            "docker": {"mounts": [{"type": "volume", "source": "saw-harness-2", "target": "/sandbox/harness", "read_only": true}]}
        });
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.multiple_drivers");
    }

    // (4) exact match — wrong target
    #[test]
    fn wrong_target_is_denied() {
        let cfg = json!({"podman": {"mounts": [
            {"type": "volume", "source": "saw-harness-1", "target": "/etc", "read_only": true}
        ]}});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.no_match");
    }

    // (4) exact match — read_only required
    #[test]
    fn writable_mount_is_denied() {
        let cfg = json!({"podman": {"mounts": [
            {"type": "volume", "source": "saw-harness-1", "target": "/sandbox/harness", "read_only": false}
        ]}});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.no_match");
    }

    // (4) exact match — source prefix
    #[test]
    fn wrong_source_prefix_is_denied() {
        let cfg = json!({"podman": {"mounts": [
            {"type": "volume", "source": "attacker-vol", "target": "/sandbox/harness", "read_only": true}
        ]}});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
    }

    // (4) exact match — mount count cap
    #[test]
    fn too_many_mounts_is_denied() {
        let cfg = json!({"podman": {"mounts": [
            {"type": "volume", "source": "saw-harness-1", "target": "/sandbox/harness", "read_only": true},
            {"type": "volume", "source": "saw-harness-2", "target": "/sandbox/harness", "read_only": true}
        ]}});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
        assert_eq!(d.reason_code, "driver_config.denied.no_match");
    }

    // (4) no extra keys on the mount
    #[test]
    fn mount_with_extra_key_is_denied() {
        let cfg = json!({"podman": {"mounts": [
            {"type": "volume", "source": "saw-harness-1", "target": "/sandbox/harness", "read_only": true, "propagation": "rshared"}
        ]}});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
    }

    // (4) no extra keys on the driver block
    #[test]
    fn driver_block_with_extra_key_is_denied() {
        let cfg = json!({"podman": {
            "mounts": [{"type": "volume", "source": "saw-harness-1", "target": "/sandbox/harness", "read_only": true}],
            "privileged": true
        }});
        let d = evaluate(Some(&harness_rule()), &cfg, false, &admin(), "podman");
        assert!(!d.allowed);
    }
}
