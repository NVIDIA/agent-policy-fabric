// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Vendors third-party protobuf sources under `contracts/third_party/<name>/proto`
//! from the pins in `contracts/third_party/pins.toml`, or checks that the
//! tree matches them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(serde::Deserialize)]
struct Pins {
    pin: Vec<Pin>,
}

#[derive(serde::Deserialize)]
struct Pin {
    name: String,
    repository: String,
    #[serde(rename = "ref")]
    git_ref: String,
    subdir: String,
}

pub fn run(check: bool) -> Result<(), String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask must live one level below the repository root")?
        .to_path_buf();
    let third_party = root.join("contracts/third_party");
    let pins_path = third_party.join("pins.toml");
    let pins: Pins = toml::from_str(
        &std::fs::read_to_string(&pins_path)
            .map_err(|e| format!("read {}: {e}", pins_path.display()))?,
    )
    .map_err(|e| format!("parse {}: {e}", pins_path.display()))?;

    let mut drift = false;
    for pin in &pins.pin {
        let dest = third_party.join(&pin.name).join("proto");
        let export = export(pin)?;
        let exported = read_tree(&export.path)?;
        let current = read_tree(&dest).unwrap_or_default();
        if exported == current {
            println!(
                "vendor-protos: {} matches {}@{}",
                pin.name, pin.repository, pin.git_ref
            );
            continue;
        }
        if check {
            drift = true;
            println!(
                "vendor-protos: {} differs from {}@{} ({} exported files, {} in tree)",
                pin.name,
                pin.repository,
                pin.git_ref,
                exported.len(),
                current.len()
            );
            for path in exported
                .keys()
                .chain(current.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                match (exported.get(path), current.get(path)) {
                    (Some(a), Some(b)) if a != b => println!("  modified: {path}"),
                    (Some(_), None) => println!("  missing in tree: {path}"),
                    (None, Some(_)) => println!("  not in export: {path}"),
                    _ => {}
                }
            }
        } else {
            write_tree(&dest, &exported)?;
            println!(
                "vendor-protos: {} updated ({} files)",
                pin.name,
                exported.len()
            );
        }
    }
    if drift {
        return Err("vendored protos differ from contracts/third_party/pins.toml; run `cargo xtask vendor-protos`".into());
    }
    Ok(())
}

struct Export {
    path: PathBuf,
}

impl Drop for Export {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn export(pin: &Pin) -> Result<Export, String> {
    let path = std::env::temp_dir().join(format!(
        "apf-vendor-protos-{}-{}",
        pin.name,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
    let export = Export { path };
    let source = format!(
        "{}#ref={},subdir={}",
        pin.repository, pin.git_ref, pin.subdir
    );
    let status = Command::new("buf")
        .args(["export", &source, "--output"])
        .arg(&export.path)
        .status()
        .map_err(|e| format!("run buf (pinned in mise.toml): {e}"))?;
    if !status.success() {
        return Err(format!("`buf export {source}` failed with {status}"));
    }
    Ok(export)
}

fn read_tree(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    collect(dir, dir, &mut files)?;
    Ok(files)
}

fn collect(base: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect(base, &path, files)?;
        } else {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let data = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            files.insert(rel, data);
        }
    }
    Ok(())
}

fn write_tree(dest: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dest);
    for (rel, data) in files {
        let path = dest.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, data).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}
