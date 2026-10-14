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
        match match_entry(allow, driver, inner) {
            Ok(()) => return Decision::allow("driver_config.allowed"),
            Err(detail) => last_detail = Some(detail),
        }
    }

    Decision::deny(
        "driver_config.denied.no_match",
        last_detail.unwrap_or_else(|| "driver config matched no allowed entry".to_string()),
    )
}

/// A mount normalized to driver-agnostic attributes. Each compute driver
/// expresses a mount differently; the normalizer below maps a driver's own
/// fields onto this one shape so a single abstract allowlist rule governs them
/// all. The rule describes the mount; APF maps each driver's syntax onto it.
#[derive(Debug)]
struct AbstractMount {
    /// Mount kind — currently always "volume" (matched against `DriverConfigMount.type`).
    kind: String,
    /// What is mounted (podman/docker `source`; kubernetes PVC `claim_name`).
    source: String,
    /// Where it lands in the sandbox (podman/docker `target`; kubernetes `mount_path`).
    target: String,
    /// Whether the mount is read-only.
    read_only: bool,
}

/// Map a driver's own mount config onto the abstract shape. Returns `Err` when a
/// driver, block, or field cannot be mapped — unmappable is a denial, never an
/// ignore, so an unrecognised driver or shape fails closed.
///
/// * `podman` / `docker` — a flat `mounts` array whose fields are already abstract
///   (`{type, source, target, read_only}`), and no key beyond that array.
/// * `kubernetes` — a Pod-style block: `volumes[]` (source = PVC `claim_name`)
///   joined by `name` to `containers.agent.volume_mounts[]` (target = `mount_path`).
fn extract_mounts(driver: &str, inner: &JsonValue) -> Result<Vec<AbstractMount>, String> {
    let obj = inner
        .as_object()
        .ok_or_else(|| "driver block is not an object".to_string())?;
    match driver {
        "podman" | "docker" => {
            // No keys beyond `mounts`: anything we cannot map is a denial.
            for key in obj.keys() {
                if key != "mounts" {
                    return Err(format!("driver block carries an unmappable key {key:?}"));
                }
            }
            let mounts = obj
                .get("mounts")
                .and_then(JsonValue::as_array)
                .ok_or_else(|| "driver block has no mounts array".to_string())?;
            mounts.iter().map(normalize_container_mount).collect()
        }
        "kubernetes" => normalize_kubernetes_mounts(obj),
        other => Err(format!("driver {other:?} has no driver-config mapping")),
    }
}

/// podman/docker: a mount is `{type, source, target, read_only}` — already abstract.
/// A mount may carry only those four fields; any extra key is a denial.
fn normalize_container_mount(mount: &JsonValue) -> Result<AbstractMount, String> {
    let obj = mount
        .as_object()
        .ok_or_else(|| "mount is not an object".to_string())?;
    const ALLOWED_KEYS: [&str; 4] = ["type", "source", "target", "read_only"];
    for key in obj.keys() {
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            return Err(format!("mount carries an unmappable key {key:?}"));
        }
    }
    Ok(AbstractMount {
        kind: str_field(obj, "type"),
        source: str_field(obj, "source"),
        target: str_field(obj, "target"),
        read_only: bool_field(obj, "read_only"),
    })
}

/// kubernetes: mounts are Pod-style — a PVC-backed `volumes[]` entry joined by
/// `name` to a `containers.agent.volume_mounts[]` entry. We map each volume
/// mount to an abstract mount: source = PVC `claim_name`, target = `mount_path`,
/// read-only if either the volume or the mount is read-only. Only PVC-backed
/// volumes are mappable; any other volume kind is a denial (fail-closed).
fn normalize_kubernetes_mounts(
    obj: &serde_json::Map<String, JsonValue>,
) -> Result<Vec<AbstractMount>, String> {
    // name -> (PVC claim_name, volume-level read_only)
    let mut claims: std::collections::HashMap<&str, (String, bool)> =
        std::collections::HashMap::new();
    for v in obj
        .get("volumes")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
    {
        let vo = v
            .as_object()
            .ok_or_else(|| "kubernetes volume is not an object".to_string())?;
        let name = vo.get("name").and_then(JsonValue::as_str).unwrap_or("");
        let pvc = vo
            .get("persistent_volume_claim")
            .and_then(JsonValue::as_object)
            .ok_or_else(|| {
                format!("kubernetes volume {name:?} is not a persistent_volume_claim")
            })?;
        claims.insert(
            name,
            (str_field(pvc, "claim_name"), bool_field(pvc, "read_only")),
        );
    }

    let volume_mounts = obj
        .get("containers")
        .and_then(|c| c.get("agent"))
        .and_then(|a| a.get("volume_mounts"))
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "kubernetes block has no containers.agent.volume_mounts".to_string())?;

    let mut out = Vec::with_capacity(volume_mounts.len());
    for m in volume_mounts {
        let mo = m
            .as_object()
            .ok_or_else(|| "kubernetes volume mount is not an object".to_string())?;
        let name = mo.get("name").and_then(JsonValue::as_str).unwrap_or("");
        let (claim_name, volume_ro) = claims
            .get(name)
            .ok_or_else(|| format!("volume mount references unknown volume {name:?}"))?;
        out.push(AbstractMount {
            kind: "volume".to_string(),
            source: claim_name.clone(),
            target: str_field(mo, "mount_path"),
            read_only: bool_field(mo, "read_only") || *volume_ro,
        });
    }
    Ok(out)
}

fn str_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> String {
    obj.get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string()
}

fn bool_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> bool {
    obj.get(key).and_then(JsonValue::as_bool).unwrap_or(false)
}

/// (4) Exact-match the request's normalized mounts against one allowed entry.
///
/// The driver's mounts are normalized to the abstract shape first; every mount
/// must then match one of the entry's mount shapes exactly, and the count must
/// stay within `max_mounts`.
fn match_entry(allow: &DriverConfigAllow, driver: &str, inner: &JsonValue) -> Result<(), String> {
    let mounts = extract_mounts(driver, inner)?;

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

    for mount in &mounts {
        if !allow.mounts.iter().any(|shape| shape_matches(shape, mount)) {
            return Err(format!(
                "mount (source={:?}, target={:?}) matches no allowed mount shape",
                mount.source, mount.target
            ));
        }
    }
    Ok(())
}

/// Whether one normalized mount matches an allowed abstract mount shape exactly.
fn shape_matches(shape: &apf_proto::ir::DriverConfigMount, mount: &AbstractMount) -> bool {
    mount.kind == shape.r#type
        && mount.target == shape.target
        && !shape.source_prefix.is_empty()
        && mount.source.starts_with(&shape.source_prefix)
        && (!shape.read_only || mount.read_only)
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

    // ── Driver-agnostic: the SAME abstract rule governs the kubernetes driver ──
    //
    // The kubernetes driver expresses a mount as a Pod-style PVC-backed volume
    // joined to a container volume mount. APF maps that onto the same abstract
    // shape (source = PVC claim_name, target = mount_path), so the harness rule
    // — authored once — admits/denies kubernetes creates too.

    fn harness_rule_k8s() -> DriverConfigPolicy {
        DriverConfigPolicy {
            deny_templates: true,
            allowed: vec![DriverConfigAllow {
                require_role: "openshell-admin".into(),
                drivers: vec!["kubernetes".into()],
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

    // A PVC-backed harness volume mounted read-only at the sanctioned path.
    fn k8s_good_config() -> JsonValue {
        json!({"kubernetes": {
            "volumes": [
                {"name": "harness", "persistent_volume_claim": {"claim_name": "saw-harness-42", "read_only": true}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "harness", "mount_path": "/sandbox/harness", "read_only": true}
            ]}}
        }})
    }

    #[test]
    fn kubernetes_pvc_harness_mount_is_admitted() {
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &k8s_good_config(),
            false,
            &admin(),
            "kubernetes",
        );
        assert!(d.allowed, "{d:?}");
        assert_eq!(d.reason_code, "driver_config.allowed");
    }

    // The mount read-only flag can also be carried on the volume (PVC) side.
    #[test]
    fn kubernetes_read_only_on_the_volume_is_admitted() {
        let cfg = json!({"kubernetes": {
            "volumes": [
                {"name": "harness", "persistent_volume_claim": {"claim_name": "saw-harness-7", "read_only": true}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "harness", "mount_path": "/sandbox/harness"}
            ]}}
        }});
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &cfg,
            false,
            &admin(),
            "kubernetes",
        );
        assert!(d.allowed, "{d:?}");
    }

    #[test]
    fn kubernetes_wrong_target_is_denied() {
        let cfg = json!({"kubernetes": {
            "volumes": [
                {"name": "harness", "persistent_volume_claim": {"claim_name": "saw-harness-42", "read_only": true}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "harness", "mount_path": "/etc", "read_only": true}
            ]}}
        }});
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &cfg,
            false,
            &admin(),
            "kubernetes",
        );
        assert!(!d.allowed);
    }

    #[test]
    fn kubernetes_non_harness_claim_is_denied() {
        let cfg = json!({"kubernetes": {
            "volumes": [
                {"name": "secret", "persistent_volume_claim": {"claim_name": "cluster-secrets", "read_only": true}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "secret", "mount_path": "/sandbox/harness", "read_only": true}
            ]}}
        }});
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &cfg,
            false,
            &admin(),
            "kubernetes",
        );
        assert!(!d.allowed);
    }

    #[test]
    fn kubernetes_writable_harness_mount_is_denied() {
        let cfg = json!({"kubernetes": {
            "volumes": [
                {"name": "harness", "persistent_volume_claim": {"claim_name": "saw-harness-42", "read_only": false}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "harness", "mount_path": "/sandbox/harness", "read_only": false}
            ]}}
        }});
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &cfg,
            false,
            &admin(),
            "kubernetes",
        );
        assert!(!d.allowed);
    }

    // A non-PVC volume kind cannot be mapped — fail closed, not ignore.
    #[test]
    fn kubernetes_non_pvc_volume_is_denied() {
        let cfg = json!({"kubernetes": {
            "volumes": [
                {"name": "harness", "host_path": {"path": "/sandbox/harness"}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "harness", "mount_path": "/sandbox/harness", "read_only": true}
            ]}}
        }});
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &cfg,
            false,
            &admin(),
            "kubernetes",
        );
        assert!(!d.allowed);
    }

    #[test]
    fn kubernetes_extra_volume_mount_exceeds_cap_and_is_denied() {
        let cfg = json!({"kubernetes": {
            "volumes": [
                {"name": "harness", "persistent_volume_claim": {"claim_name": "saw-harness-1", "read_only": true}},
                {"name": "extra", "persistent_volume_claim": {"claim_name": "saw-harness-2", "read_only": true}}
            ],
            "containers": {"agent": {"volume_mounts": [
                {"name": "harness", "mount_path": "/sandbox/harness", "read_only": true},
                {"name": "extra", "mount_path": "/sandbox/harness", "read_only": true}
            ]}}
        }});
        let d = evaluate(
            Some(&harness_rule_k8s()),
            &cfg,
            false,
            &admin(),
            "kubernetes",
        );
        assert!(!d.allowed);
    }

    // An unknown driver has no mapping at all — deny, never admit by default.
    #[test]
    fn unknown_driver_is_denied() {
        let cfg = json!({"firecracker": {"mounts": [
            {"type": "volume", "source": "saw-harness-1", "target": "/sandbox/harness", "read_only": true}
        ]}});
        let rule = DriverConfigPolicy {
            deny_templates: true,
            allowed: vec![DriverConfigAllow {
                require_role: "openshell-admin".into(),
                drivers: vec!["firecracker".into()],
                max_mounts: 1,
                mounts: vec![DriverConfigMount {
                    r#type: "volume".into(),
                    source_prefix: "saw-harness-".into(),
                    target: "/sandbox/harness".into(),
                    read_only: true,
                }],
            }],
        };
        let d = evaluate(Some(&rule), &cfg, false, &admin(), "firecracker");
        assert!(!d.allowed);
    }
}
