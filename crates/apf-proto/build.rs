// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};
use std::process::Command;

// APF IR types: PolicyRule (incl. PolicyRuleRole), SandboxPolicy, PolicyBundle,
// Provider, PolicyEffect, PolicyFinding, etc.
const APF_CORE_MODULE: &str = "REDACTED-SCHEMA-REGISTRY/agent-policy-fabric/core";

// OpenShell protos remain pinned together except for supervisor middleware. The middleware
// authentication field is additive on the wire, so consuming it independently avoids pulling
// unrelated source-level changes into the sandbox and gateway contracts.
const OPENSHELL_COMMIT: &str = "eb380d71a3e40952ed7d6944f5e63e54bd262470";
const OPENSHELL_MIDDLEWARE_AUTH_COMMIT: &str = "bdabb54cb361a59d4eba957a8cdfd85ae5858289";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contracts = manifest_dir.join("../../contracts/proto");

    let v1 = "nvidia/agent_policy_fabric/policy/v1alpha1";

    // --- APF core IR types: use vendored copy if present, else fetch from BSR ---
    // Vendored: run `mise run vendor-proto` once locally, commit contracts/proto-ir/.
    // Docker builds then work without buf or BSR credentials.
    let vendor_dir = manifest_dir.join("../../contracts/proto-ir");
    let apf_export =
        if vendor_dir.exists() && vendor_dir.join(v1).join("policy_rule.proto").exists() {
            println!("cargo:warning=apf-proto: using vendored proto-ir (contracts/proto-ir/)");
            vendor_dir.clone()
        } else {
            let d = out_dir.join("apf-core-export");
            export_bsr(APF_CORE_MODULE, &d)?;
            d
        };
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
        "host_tool_policy.proto",
        "policy_definition.proto",
        "policy_data.proto",
    ]
    .iter()
    .map(|f| apf_export.join(v1).join(f))
    .collect();

    // --- Fetch OpenShell sandbox.proto from git ---
    let os_export = out_dir.join("openshell-proto-export");
    export_openshell(&os_export, OPENSHELL_COMMIT)?;
    let middleware_export = out_dir.join("openshell-middleware-proto-export");
    export_openshell_proto(
        &middleware_export,
        OPENSHELL_MIDDLEWARE_AUTH_COMMIT,
        "supervisor_middleware.proto",
    )?;
    let sandbox_proto = os_export.join("sandbox.proto");
    let gateway_interceptor = os_export.join("gateway_interceptor.proto");
    let supervisor_middleware = middleware_export.join("supervisor_middleware.proto");
    let datamodel_proto = os_export.join("datamodel.proto");
    let openshell_proto = os_export.join("openshell.proto");

    if !supervisor_middleware.is_file() {
        return Err(format!(
            "OpenShell supervisor_middleware.proto is missing from pinned commit {OPENSHELL_MIDDLEWARE_AUTH_COMMIT}"
        )
        .into());
    }

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
            &[
                apf_export.as_path(),
                middleware_export.as_path(),
                os_export.as_path(),
                contracts.as_path(),
            ],
        )?;

    Ok(())
}

fn export_bsr(module: &str, out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out)?;
    let status = Command::new("buf")
        .args(["export", module, "--output"])
        .arg(out)
        .status()
        .map_err(|e| format!("could not run `buf export {module}`: {e}"))?;
    if !status.success() {
        return Err(format!("`buf export {module}` failed with {status}").into());
    }
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

fn export_openshell_proto(
    out: &Path,
    commit: &str,
    proto: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out)?;
    let source = format!("https://github.com/NVIDIA/OpenShell.git#ref={commit},subdir=proto");
    let status = Command::new("buf")
        .args(["export", &source, "--output"])
        .arg(out)
        .args(["--path", proto, "--exclude-imports"])
        .status()
        .map_err(|error| format!("could not export {proto} from OpenShell {commit}: {error}"))?;
    if !status.success() {
        return Err(format!("failed to export {proto} from OpenShell {commit}: {status}").into());
    }
    Ok(())
}
