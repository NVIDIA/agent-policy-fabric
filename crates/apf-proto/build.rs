// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contracts = manifest_dir.join("../../contracts/proto");
    // OpenShell wire contracts, vendored at the revision recorded in
    // contracts/third_party/pins.toml. Refresh with `cargo xtask vendor-protos`.
    let openshell = manifest_dir.join("../../contracts/third_party/openshell/proto");

    let v1 = "nvidia/agent_policy_fabric/policy/v1alpha1";

    // APF core IR types: PolicyRule (incl. PolicyRuleRole), SandboxPolicy,
    // Provider, PolicyEffect, PolicyFinding, etc.
    let ir_protos: Vec<PathBuf> = [
        "object_meta.proto",
        "policy_rule.proto",
        "policy_annotator.proto",
        "policy_set.proto",
        "provider_profile_set.proto",
        "sandbox_policy.proto",
        "provider.proto",
        "policy_effect.proto",
        "policy_finding.proto",
    ]
    .iter()
    .map(|f| contracts.join(v1).join(f))
    .collect();

    let openshell_protos: Vec<PathBuf> = [
        "sandbox.proto",
        "extension.proto",
        "gateway_interceptor.proto",
        "supervisor_middleware.proto",
        "datamodel.proto",
        "openshell.proto",
    ]
    .iter()
    .map(|f| openshell.join(f))
    .collect();
    for p in &openshell_protos {
        if !p.exists() {
            return Err(format!(
                "missing vendored OpenShell proto {}; run `cargo xtask vendor-protos`",
                p.display()
            )
            .into());
        }
    }

    // Local wire surface protos.
    let local_protos: Vec<PathBuf> = [
        "nvidia/agent_policy_fabric/runtime/v1alpha1/runtime.proto",
        "nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto",
        "nvidia/agent_policy_fabric/pip/v1alpha1/pip.proto",
        "nvidia/agent_policy_fabric/policy_service/v1alpha1/policy_service.proto",
    ]
    .iter()
    .map(|f| contracts.join(f))
    .collect();

    let mut all_protos: Vec<PathBuf> = ir_protos;
    all_protos.extend(openshell_protos);
    all_protos.extend(local_protos);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", contracts.display());
    println!("cargo:rerun-if-changed={}", openshell.display());

    let descriptor_path = out_dir.join("descriptor.bin");

    // `protoc` comes from PATH (or `PROTOC`); `mise install` provides the pinned version.
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            &all_protos.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
            &[openshell.as_path(), contracts.as_path()],
        )?;

    Ok(())
}
