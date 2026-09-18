// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};
use std::process::Command;

// APF IR types: PolicyRule (incl. PolicyRuleRole), SandboxPolicy,
// Provider, PolicyEffect, PolicyFinding, etc.
const OPENSHELL_COMMIT: &str = "8d67250a5d17348eb96c4fa46226b06d8041f2ba";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contracts = manifest_dir.join("../../contracts/proto");

    let v1 = "nvidia/agent_policy_fabric/policy/v1alpha1";

    // --- APF core IR types: checked-in copy from the APF contract module. ---
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

    // --- Fetch OpenShell protos from git ---
    let os_export = out_dir.join("openshell-proto-export");
    export_openshell(&os_export, OPENSHELL_COMMIT)?;
    let sandbox_proto = os_export.join("sandbox.proto");
    let gateway_interceptor = os_export.join("gateway_interceptor.proto");
    let supervisor_middleware = os_export.join("supervisor_middleware.proto");
    let datamodel_proto = os_export.join("datamodel.proto");
    let openshell_proto = os_export.join("openshell.proto");

    // --- Local wire surface protos ---
    let local_protos: Vec<PathBuf> = [
        "nvidia/agent_policy_fabric/runtime/v1alpha1/runtime.proto",
        "nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto",
        "nvidia/agent_policy_fabric/policy_service/v1alpha1/policy_service.proto",
    ]
    .iter()
    .map(|f| contracts.join(f))
    .collect();

    let mut all_protos: Vec<PathBuf> = ir_protos;
    for p in [
        &sandbox_proto,
        &gateway_interceptor,
        &supervisor_middleware,
        &datamodel_proto,
        &openshell_proto,
    ] {
        if p.exists() {
            all_protos.push(p.clone());
        }
    }
    all_protos.extend(local_protos);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", contracts.display());

    let descriptor_path = out_dir.join("descriptor.bin");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            &all_protos.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
            &[os_export.as_path(), contracts.as_path()],
        )?;

    Ok(())
}

fn export_openshell(out: &Path, commit: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out)?;
    let source = format!("https://github.com/NVIDIA/OpenShell.git#ref={commit},subdir=proto");
    let status = Command::new("buf")
        .args(["export", &source, "--output"])
        .arg(out)
        .status();
    let success = status.as_ref().is_ok_and(|s| s.success());
    if !success {
        eprintln!("Warning: `buf export {source}` failed, falling back to empty sandbox proto");
        // Write a minimal stub so the build doesn't fail in environments
        // without network access. Consumers that need SandboxPolicy will get
        // a compile error pointing them here.
        std::fs::write(
            out.join("sandbox.proto"),
            b"syntax = \"proto3\";\npackage openshell.sandbox.v1;\n// stub\n",
        )?;
    }
    Ok(())
}
