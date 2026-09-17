// SPDX-License-Identifier: Apache-2.0
//! Host-qualified instance ids on emitted records.

use apf_audit::{AuditIdentity, ComponentAudit, host_qualified_instance_id};
use uuid::Uuid;

const IDENTITY: AuditIdentity = AuditIdentity {
    component_name: "apf-host-context-test",
    enforcement_point_id: "apf-host-context-test:seam",
    runtime_substrate: "none",
    trust_root_id: "apf-root-dev",
    version: "0.0.0",
};

#[test]
fn instance_id_is_host_qualified() {
    let qualified = host_qualified_instance_id(IDENTITY.enforcement_point_id);
    assert!(
        qualified.starts_with(IDENTITY.enforcement_point_id),
        "{qualified}"
    );
    assert!(
        qualified.contains('@'),
        "hostname missing from {qualified}; test host has no hostname?"
    );

    let dir = std::env::temp_dir().join(format!("apf-host-context-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = ComponentAudit::to_jsonl_in(&dir, IDENTITY).unwrap();
    let common = audit.common(&"a".repeat(64), None).unwrap();
    assert_eq!(common.component.instance_id, qualified);
}
