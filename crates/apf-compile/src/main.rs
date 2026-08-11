// SPDX-License-Identifier: Apache-2.0
//! APF bundle compilation and fixture generation tool.
//!
//! Subcommands:
//!   compile     Verify and compile a signed policy bundle offline
//!   genfixture  Generate a signed bundle fixture from a template

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use apf_bundle::{CounterStore, Ed25519Signer, Ed25519Verifier, TrustStore, verify_bundle};
use apf_compiler::Compiler;
use apf_types::{BundleSigner, BundleVerifier};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "apf-compile", about = "APF bundle compilation and fixture generation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verify and compile a signed policy bundle offline
    Compile(CompileArgs),
    /// Generate a signed bundle fixture from a template
    Genfixture(GenfixtureArgs),
}

// ── compile ───────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
struct CompileArgs {
    /// Path to the signed bundle manifest YAML.
    #[arg(long)]
    bundle_path: PathBuf,

    /// Directory containing trust-root public keys (`*.pub` files).
    #[arg(long, default_value = "./trust-roots")]
    trust_root_dir: PathBuf,

    /// Key id to verify the bundle signature against.
    #[arg(long, default_value = "apf-dev")]
    key_id: String,

    /// Only verify; skip compilation and projection output.
    #[arg(long)]
    verify_only: bool,
}

// ── genfixture ────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
struct GenfixtureArgs {
    /// Bundle template YAML with `sha256: REPLACE_WITH_DIGEST` placeholders.
    #[arg(long)]
    template: PathBuf,

    /// Directory containing member files referenced by the template.
    /// Defaults to the template's parent directory.
    #[arg(long)]
    members_dir: Option<PathBuf>,

    /// Ed25519 signing key seed file (`ed25519:<base64>` format).
    #[arg(long)]
    sign_key: PathBuf,

    /// Key id to stamp in the signature.
    #[arg(long, default_value = "apf-dev")]
    key_id: String,

    /// Output path for the signed artifact. Defaults to `<template-stem>.yaml`
    /// in the current directory.
    #[arg(long)]
    output: Option<PathBuf>,
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn load_signing_key(path: &Path) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read signing key {}: {e}", path.display()))?;
    let line = raw
        .lines()
        .find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .ok_or_else(|| anyhow::anyhow!("signing key file is empty: {}", path.display()))?
        .trim();
    let b64 = line.strip_prefix("ed25519:").ok_or_else(|| {
        anyhow::anyhow!("signing key {}: expected `ed25519:` prefix", path.display())
    })?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
    if raw.len() != 32 {
        anyhow::bail!("expected 32-byte seed, got {}", raw.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ── compile handler ───────────────────────────────────────────────────────────

fn run_compile(args: CompileArgs) -> anyhow::Result<()> {
    let trust_store = TrustStore::load_from_dir(&args.trust_root_dir)
        .map_err(|e| anyhow::anyhow!("load trust roots: {e}"))?;
    let vk = trust_store
        .get(&args.key_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no trust root for key id '{}'", args.key_id))?;
    let verifier = Ed25519Verifier::new(vk);

    let bundle_bytes = std::fs::read(&args.bundle_path)
        .map_err(|e| anyhow::anyhow!("read bundle: {e}"))?;

    let counter_store = CounterStore::load_or_init(
        &std::env::temp_dir().join(format!("apf-compile-{}.counter", std::process::id())),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let outcome = verify_bundle(
        &bundle_bytes,
        &args.bundle_path,
        &verifier as &dyn BundleVerifier,
        &counter_store,
        SystemTime::now(),
        &HashMap::new(),
    );
    if !outcome.ok {
        anyhow::bail!("verification failed: {:?}", outcome.rejection_reasons);
    }
    println!("verified  digest={} counter={}", outcome.digest_hex, outcome.monotonic_counter);

    if !args.verify_only {
        let compiler = Compiler::new(vec![]);
        let parsed = apf_bundle::parse_bundle(&bundle_bytes)
            .map_err(|e| anyhow::anyhow!("parse bundle: {e}"))?;
        let bundle_dir = args.bundle_path.parent().unwrap_or_else(|| Path::new("."));
        let members = parsed
            .load_members(bundle_dir)
            .map_err(|e| anyhow::anyhow!("load members: {e}"))?;
        let compiled = compiler
            .lower_members(&members, None)
            .map_err(|e| anyhow::anyhow!("compile: {e}"))?;
        if compiled.surfaces.is_empty() {
            println!("warning: no projections produced (no projectors registered)");
        }
        for s in &compiled.surfaces {
            println!("projection  kind={} name={} bytes={}", s.kind, s.name, s.bytes.len());
        }
    }
    Ok(())
}

// ── genfixture handler ────────────────────────────────────────────────────────

fn run_genfixture(args: GenfixtureArgs) -> anyhow::Result<()> {
    let members_dir = args.members_dir.unwrap_or_else(|| {
        args.template
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    let template_str = std::fs::read_to_string(&args.template)
        .map_err(|e| anyhow::anyhow!("read template: {e}"))?;

    // Fill REPLACE_WITH_DIGEST placeholders with actual SHA-256 values.
    let mut filled = template_str.clone();
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&template_str).map_err(|e| anyhow::anyhow!("parse template: {e}"))?;
    if let Some(manifest) = parsed.get("manifest").and_then(|v| v.as_sequence()) {
        for entry in manifest {
            if let (Some(path_val), Some(sha_val)) = (
                entry.get("path").and_then(|v| v.as_str()),
                entry.get("sha256").and_then(|v| v.as_str()),
            ) {
                if sha_val.to_uppercase() == "REPLACE_WITH_DIGEST" {
                    let member_path = members_dir.join(path_val);
                    let bytes = std::fs::read(&member_path).map_err(|e| {
                        anyhow::anyhow!("read member {}: {e}", member_path.display())
                    })?;
                    let digest = sha256_hex(&bytes);
                    filled = filled.replace(
                        &format!("sha256: {sha_val}"),
                        &format!("sha256: {digest}"),
                    );
                }
            }
        }
    }

    let sk = load_signing_key(&args.sign_key)?;
    let signer = Ed25519Signer::new(sk);
    let artifact = signer
        .sign(filled.as_bytes())
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    let output = args.output.unwrap_or_else(|| {
        let stem = args.template.file_stem().unwrap_or_default().to_string_lossy();
        PathBuf::from(format!("{stem}.yaml"))
    });
    std::fs::write(&output, &artifact)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", output.display()))?;
    println!(
        "wrote {} ({} bytes sha256={})",
        output.display(),
        artifact.len(),
        sha256_hex(&artifact)
    );
    Ok(())
}

// ── entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Compile(args) => run_compile(args),
        Commands::Genfixture(args) => run_genfixture(args),
    }
}
