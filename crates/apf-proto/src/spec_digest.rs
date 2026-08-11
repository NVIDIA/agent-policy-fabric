// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Canonical spec-digest computation shared between the APF Policy Service and the
//! OpenShell interceptor.
//!
//! The digest is the hex-encoded SHA-256 of the canonical JSON form of
//! `{ "policy": <SandboxPolicy> }`. The policy object is serialized to
//! proto3-JSON via the compiled descriptor (prost-reflect), so it is
//! byte-identical to what the gateway produces when it re-encodes the admitted
//! object for VALIDATE — default-valued fields omitted, camelCase names,
//! 64-bit integers stringified. Object keys are then sorted lexicographically
//! at every nesting level before hashing so the value is stable across
//! JSON↔Protobuf round-trips.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::openshell_sandbox::SandboxPolicy;

/// Fully-qualified name of the message serialized for the spec-digest.
const SANDBOX_POLICY_FQN: &str = "openshell.sandbox.v1.SandboxPolicy";

/// Descriptor pool built from the self-contained set emitted at build time.
static DESCRIPTOR_POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin")).as_ref())
        .expect("compiled descriptor set decodes")
});

/// Returns hex-encoded SHA-256 of the canonical JSON form of `{ "policy": <policy> }`.
///
/// Uses camelCase protobuf JSON field names so the digest matches what the
/// gateway reconstructs when re-encoding the admitted object for VALIDATE.
#[must_use]
pub fn sandbox_policy_spec_digest(policy: &SandboxPolicy) -> String {
    let policy_value = sandbox_policy_to_json(policy);
    let digest_input = serde_json::json!({ "policy": policy_value });
    canonical_json_digest(&digest_input)
}

/// Returns hex-encoded SHA-256 of the canonical (key-sorted) JSON serialization of `value`.
#[must_use]
pub fn canonical_json_digest(value: &JsonValue) -> String {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical).expect("valid JSON serializes infallibly");
    hex::encode(Sha256::digest(&bytes))
}

fn canonicalize(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            JsonValue::Object(sorted.into_iter().collect())
        }
        JsonValue::Array(arr) => JsonValue::Array(arr.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Serialize a `SandboxPolicy` to canonical proto3-JSON via the compiled
/// descriptor.
///
/// The output matches the gateway's own proto-JSON re-encoding: default-valued
/// fields omitted, camelCase field names, enum names, 64-bit integers as
/// strings. Shared by the APF Policy Service (digest input) and the interceptor (both the
/// spec-digest recompute and the injected `/spec/policy` patch) so all sides
/// agree on one representation.
#[must_use]
pub fn sandbox_policy_to_json(policy: &SandboxPolicy) -> JsonValue {
    let descriptor = DESCRIPTOR_POOL
        .get_message_by_name(SANDBOX_POLICY_FQN)
        .expect("SandboxPolicy descriptor present in pool");
    let bytes = policy.encode_to_vec();
    let dynamic = DynamicMessage::decode(descriptor, bytes.as_ref())
        .expect("SandboxPolicy bytes decode against its descriptor");
    dynamic
        .serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
        .expect("dynamic message serializes to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openshell_sandbox::{FilesystemPolicy, LandlockPolicy, ProcessPolicy, SandboxPolicy};

    #[test]
    fn spec_digest_is_64_hex_chars() {
        let policy = SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/etc".to_string()],
                read_write: vec![],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProcessPolicy {
                run_as_user: "nobody".to_string(),
                run_as_group: "nogroup".to_string(),
            }),
            network_policies: std::collections::HashMap::new(),
            network_middlewares: std::collections::HashMap::new(),
        };
        let digest = sandbox_policy_spec_digest(&policy);
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn spec_digest_is_deterministic() {
        let policy = SandboxPolicy {
            version: 1,
            filesystem: None,
            landlock: None,
            process: None,
            network_policies: std::collections::HashMap::new(),
            network_middlewares: std::collections::HashMap::new(),
        };
        assert_eq!(
            sandbox_policy_spec_digest(&policy),
            sandbox_policy_spec_digest(&policy)
        );
    }

    #[test]
    fn spec_digest_differs_on_value_change() {
        let p1 = SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec![],
                read_write: vec![],
            }),
            landlock: None,
            process: None,
            network_policies: std::collections::HashMap::new(),
            network_middlewares: std::collections::HashMap::new(),
        };
        let p2 = SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                read_only: vec![],
                read_write: vec![],
            }),
            landlock: None,
            process: None,
            network_policies: std::collections::HashMap::new(),
            network_middlewares: std::collections::HashMap::new(),
        };
        assert_ne!(
            sandbox_policy_spec_digest(&p1),
            sandbox_policy_spec_digest(&p2)
        );
    }
}
