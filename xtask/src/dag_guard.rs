// SPDX-License-Identifier: Apache-2.0
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

pub fn run() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .map_err(|e| format!("dag-guard: failed to run cargo metadata: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Empty virtual workspace is not an error for dag-guard.
        if stderr.contains("has no members") || stderr.contains("no package") {
            println!("dag-guard: empty workspace — ok");
            return Ok(());
        }
        return Err(format!("dag-guard: cargo metadata failed:\n{stderr}"));
    }

    let meta: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("dag-guard: metadata parse error: {e}"))?;

    let workspace_root = PathBuf::from(
        meta["workspace_root"].as_str().unwrap_or("."),
    );

    let packages = match meta["packages"].as_array() {
        Some(p) if !p.is_empty() => p,
        _ => {
            println!("dag-guard: no packages — ok");
            return Ok(());
        }
    };

    // Classify each workspace package.
    //
    // Kinds (mutually exclusive, checked in order):
    //   service  — [[bin]] + publish = false  (deployable binary)
    //   adapter  — name starts with "apf-openshell-"  (substrate adapter; no library imports these)
    //   library  — everything else in crates/
    //   xtask    — the xtask crate
    struct Pkg {
        name: String,
        is_service: bool,
        is_adapter: bool,
        in_crates: bool,
    }

    // Adapter name prefixes — extend when adding new substrate adapters.
    const ADAPTER_PREFIXES: &[&str] = &["apf-openshell-"];

    let root_str = workspace_root.to_string_lossy();

    let classified: Vec<Pkg> = packages
        .iter()
        .map(|p| {
            let name = p["name"].as_str().unwrap_or("").to_string();
            let manifest = p["manifest_path"].as_str().unwrap_or("");
            let rel = manifest
                .strip_prefix(root_str.as_ref())
                .unwrap_or(manifest)
                .trim_start_matches('/');

            let in_crates = rel.starts_with("crates/");

            // Service: [[bin]] target AND publish = false (empty array in metadata)
            let has_bin = p["targets"].as_array().is_some_and(|ts| {
                ts.iter().any(|t| {
                    t["kind"]
                        .as_array()
                        .is_some_and(|ks| ks.iter().any(|k| k.as_str() == Some("bin")))
                })
            });
            let publish_false =
                matches!(p["publish"].as_array(), Some(arr) if arr.is_empty());
            let is_service = in_crates && has_bin && publish_false;

            // Adapter: name matches a known substrate adapter prefix.
            let is_adapter = in_crates
                && !is_service
                && ADAPTER_PREFIXES.iter().any(|pfx| name.starts_with(pfx));

            Pkg { name, in_crates, is_service, is_adapter }
        })
        .collect();

    // Name → (is_service, is_adapter) lookup for checking dependencies.
    let pkg_map: HashMap<&str, (bool, bool)> = classified
        .iter()
        .map(|p| (p.name.as_str(), (p.is_service, p.is_adapter)))
        .collect();

    let mut errors: Vec<String> = Vec::new();

    // DAG rules:
    //   Rule 1 — service → service
    //   Rule 2 — library → service or library → adapter
    //   Rule 3 — adapter → adapter
    for (pkg, raw) in classified.iter().zip(packages.iter()) {
        let deps = raw["dependencies"].as_array().map_or(&[][..], |v| v);
        for dep in deps {
            if !dep["source"].is_null() {
                continue;
            }
            let dep_name = dep["name"].as_str().unwrap_or("");
            let Some(&(dep_is_service, dep_is_adapter)) = pkg_map.get(dep_name) else {
                continue;
            };

            if pkg.is_service && dep_is_service {
                errors.push(format!(
                    "dag-guard: FAIL service→service: {} depends on {} via path",
                    pkg.name, dep_name,
                ));
            }

            let is_library = pkg.in_crates && !pkg.is_service && !pkg.is_adapter;
            if is_library {
                if dep_is_service {
                    errors.push(format!(
                        "dag-guard: FAIL library→service: {} depends on {} via path",
                        pkg.name, dep_name,
                    ));
                }
                if dep_is_adapter {
                    errors.push(format!(
                        "dag-guard: FAIL library→adapter: {} depends on {} via path",
                        pkg.name, dep_name,
                    ));
                }
            }

            if pkg.is_adapter && dep_is_adapter {
                errors.push(format!(
                    "dag-guard: FAIL adapter→adapter: {} depends on {} via path",
                    pkg.name, dep_name,
                ));
            }
        }
    }

    // Rule 4 — no openshell_ imports in library crate source.
    //
    // Collect non-library crate names so we can skip their src dirs.
    let non_library_names: Vec<&str> = classified
        .iter()
        .filter(|p| p.is_service || p.is_adapter)
        .map(|p| p.name.as_str())
        .collect();

    let crates_dir = workspace_root.join("crates");
    if crates_dir.exists() {
        let rg = Command::new("rg")
            .args(["--files-with-matches", "openshell_|runtimes::", "crates/"])
            .current_dir(&workspace_root)
            .output();

        if let Ok(o) = rg {
            if o.status.success() {
                let matches = String::from_utf8_lossy(&o.stdout);
                for line in matches.lines() {
                    let in_non_library = non_library_names.iter().any(|svc| {
                        line.contains(&format!("crates/{svc}/"))
                    });
                    if !in_non_library {
                        errors.push(format!(
                            "dag-guard: FAIL openshell_ import in library: {line}"
                        ));
                    }
                }
            }
        }
    }

    // Rule 4 — yaml_sigil_ outside the allowlisted private backend file.
    const ALLOWLIST: &str = "crates/apf-policy-service/src/signing/yaml_sigil_backend.rs";

    if crates_dir.exists() {
        let rg = Command::new("rg")
            .args(["--files-with-matches", "yaml_sigil_", "crates/"])
            .current_dir(&workspace_root)
            .output();

        if let Ok(o) = rg {
            if o.status.success() {
                let matches = String::from_utf8_lossy(&o.stdout);
                for line in matches.lines() {
                    if !line.contains(ALLOWLIST) {
                        errors.push(format!(
                            "dag-guard: FAIL yaml_sigil_ outside allowlist: {line}"
                        ));
                    }
                }
            }
        }
    }

    // Rule 5 — library crates must not resolve only via private registry.
    // Best-effort: flag any workspace dependency whose source contains "nvidia"
    // and has no crates.io fallback.
    for (pkg, raw) in classified.iter().zip(packages.iter()) {
        if !pkg.in_crates || pkg.is_service || pkg.is_adapter {
            continue;
        }
        let deps = raw["dependencies"].as_array().map_or(&[][..], |v| v);
        for dep in deps {
            if let Some(src) = dep["source"].as_str() {
                if src.contains("nvidia") && !src.contains("crates.io") {
                    // Only warn; resolving registries accurately needs full metadata.
                    eprintln!(
                        "dag-guard: WARN library {} has private-registry dep: {}",
                        pkg.name,
                        dep["name"].as_str().unwrap_or("?"),
                    );
                }
            }
        }
    }

    if errors.is_empty() {
        println!("dag-guard: all checks passed");
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}
