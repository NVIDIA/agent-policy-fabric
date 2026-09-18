// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Declares the InterceptorBindings this interceptor registers with the gateway.

use crate::proto::{
    GatewayInterceptorPhase, InterceptorBinding, InterceptorManifest, InterceptorSelector,
};

#[must_use]
pub fn manifest() -> InterceptorManifest {
    InterceptorManifest {
        name: "apf/policy-adapter".to_string(),
        failure_policy: "fail_closed".to_string(),
        provider_profiles: true,
        // The real audience is instance-specific (depends on the configured
        // trust profile) and is set by `GatewayInterceptorService::describe`
        // before this manifest reaches a caller.
        expected_audience: String::new(),
        bindings: vec![
            sandbox_policy_inject(),
            sandbox_policy_verify(),
            sandbox_policy_refresh(),
            config_policy_verify(),
            provider_instance_create_verify(),
            provider_instance_update_verify(),
            provider_profile_import_verify(),
            provider_profile_update_verify(),
            provider_profile_delete_verify(),
            policy_analysis_verify(),
            draft_chunk_approve_verify(),
            draft_chunk_approve_all_verify(),
            sandbox_policy_post_commit(),
            config_policy_post_commit(),
        ],
    }
}

fn sandbox_policy_post_commit() -> InterceptorBinding {
    InterceptorBinding {
        id: "sandbox-policy-post-commit".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::PostCommit as i32],
        failure_policy: "fail_open".to_string(),
    }
}

fn config_policy_post_commit() -> InterceptorBinding {
    InterceptorBinding {
        id: "config-policy-post-commit".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/UpdateConfig".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::PostCommit as i32],
        failure_policy: "fail_open".to_string(),
    }
}

fn sandbox_policy_inject() -> InterceptorBinding {
    InterceptorBinding {
        id: "sandbox-policy-inject".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::ModifyOperation as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn sandbox_policy_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "sandbox-policy-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn sandbox_policy_refresh() -> InterceptorBinding {
    InterceptorBinding {
        id: "sandbox-policy-refresh".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/UpdateConfig".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::ModifyOperation as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn config_policy_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "config-policy-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/UpdateConfig".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn provider_instance_create_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "provider-instance-create-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/CreateProvider".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn provider_instance_update_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "provider-instance-update-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/UpdateProvider".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn provider_profile_import_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "provider-profile-import-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/ImportProviderProfiles".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn provider_profile_update_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "provider-profile-update-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/UpdateProviderProfiles".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn provider_profile_delete_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "provider-profile-delete-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/DeleteProviderProfile".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn policy_analysis_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "policy-analysis-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/SubmitPolicyAnalysis".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn draft_chunk_approve_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "draft-chunk-approve-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/ApproveDraftChunk".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn draft_chunk_approve_all_verify() -> InterceptorBinding {
    InterceptorBinding {
        id: "draft-chunk-approve-all-verify".to_string(),
        selector: Some(InterceptorSelector {
            rpc: "openshell.v1.OpenShell/ApproveAllDraftChunks".to_string(),
            ..Default::default()
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_fourteen_bindings() {
        assert_eq!(manifest().bindings.len(), 14);
    }

    #[test]
    fn manifest_name_is_set() {
        assert_eq!(manifest().name, "apf/policy-adapter");
    }

    #[test]
    fn manifest_failure_policy_is_fail_closed() {
        assert_eq!(manifest().failure_policy, "fail_closed");
    }

    #[test]
    fn sandbox_policy_verify_is_fail_closed() {
        let m = manifest();
        let b = m
            .bindings
            .iter()
            .find(|b| b.id == "sandbox-policy-verify")
            .unwrap();
        assert_eq!(b.failure_policy, "fail_closed");
        assert_eq!(b.phases, vec![GatewayInterceptorPhase::Validate as i32]);
    }

    #[test]
    fn provider_profile_import_verify_is_validate_phase() {
        let m = manifest();
        let b = m
            .bindings
            .iter()
            .find(|b| b.id == "provider-profile-import-verify")
            .unwrap();
        assert_eq!(b.phases, vec![GatewayInterceptorPhase::Validate as i32]);
    }

    #[test]
    fn provider_profile_update_and_delete_verify_exist() {
        let m = manifest();
        assert!(
            m.bindings
                .iter()
                .any(|b| b.id == "provider-profile-import-verify")
        );
        assert!(
            m.bindings
                .iter()
                .any(|b| b.id == "provider-profile-update-verify")
        );
        assert!(
            m.bindings
                .iter()
                .any(|b| b.id == "provider-profile-delete-verify")
        );
    }

    #[test]
    fn provider_instance_bindings_are_validate_phase() {
        let m = manifest();
        for id in &[
            "provider-instance-create-verify",
            "provider-instance-update-verify",
        ] {
            let b = m.bindings.iter().find(|b| b.id == *id).unwrap();
            assert_eq!(b.phases, vec![GatewayInterceptorPhase::Validate as i32]);
            assert_eq!(b.failure_policy, "fail_closed");
        }
    }
}
