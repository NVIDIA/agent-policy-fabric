// SPDX-License-Identifier: Apache-2.0
//! APF bundle compilation and fixture generation tool.
//!
//! Subcommands:
//!   compile     Verify and compile a signed policy bundle offline
//!   genfixture  Generate a yaml-sigil signed bundle fixture from a template

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use apf_bundle::{CounterStore, TrustStore, YamlSigilVerifier, verify_bundle};
use apf_compiler::Compiler;
use apf_types::BundleVerifier;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use yaml_sigil_signing::{OutputForm, SignOutcome, SignRequest, SigningKey as SigilKey};
use yaml_sigil_traits::AlgorithmId;

#[derive(Debug, Parser)]
#[command(
    name = "apf-compile",
    about = "APF bundle compilation and fixture generation"
)]
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

    /// Output path for the signed yaml-sigil artifact.
    #[arg(long)]
    out: PathBuf,

    /// Ed25519 signing key seed file (`ed25519:<base64>` format).
    /// Pass `--generate-key` to create a new keypair if the file does not exist.
    #[arg(long)]
    key: PathBuf,

    /// Base directory for resolving manifest member paths.
    /// Defaults to the template's parent directory.
    #[arg(long)]
    base_dir: Option<PathBuf>,

    /// Generate a new Ed25519 keypair into --key (and a sibling `.pub`)
    /// if the key file does not already exist.
    #[arg(long)]
    generate_key: bool,

    /// Where to write the generated public key. Defaults to `<key>.pub`.
    #[arg(long)]
    pubkey_out: Option<PathBuf>,

    /// Key id stamped into the yaml-sigil signature carrier. Must match the
    /// `.pub` filename stem loaded by the service trust store.
    /// Defaults to the `--key` file stem.
    #[arg(long)]
    keyid: Option<String>,
}

// ── helpers ───────────────────────────────────────────────────────────────────

const KEY_PREFIX: &str = "ed25519:";

fn load_or_generate_key(
    path: &Path,
    generate_if_missing: bool,
    pubkey_out: &Option<PathBuf>,
) -> anyhow::Result<ed25519_dalek::SigningKey> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read key {}: {e}", path.display()))?;
        let line = raw
            .lines()
            .find(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .ok_or_else(|| anyhow::anyhow!("key file empty: {}", path.display()))?
            .trim();
        let b64 = line
            .strip_prefix(KEY_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("key must start with `{KEY_PREFIX}`"))?;
        let seed = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
        if seed.len() != 32 {
            anyhow::bail!("expected 32-byte seed, got {}", seed.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed);
        return Ok(ed25519_dalek::SigningKey::from_bytes(&arr));
    }

    if !generate_if_missing {
        anyhow::bail!(
            "key file {} does not exist; pass --generate-key to create",
            path.display()
        );
    }

    use rand::RngCore as _;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let seed_b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    std::fs::write(
        path,
        format!(
            "# DEV-ONLY Ed25519 signing key. Do not use in production.\n{KEY_PREFIX}{seed_b64}\n"
        ),
    )?;
    println!("generated dev signing key at {}", path.display());

    let pub_path = pubkey_out
        .clone()
        .unwrap_or_else(|| path.with_extension("pub"));
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    std::fs::write(
        &pub_path,
        format!("# DEV-ONLY Ed25519 verifying key.\n{KEY_PREFIX}{pub_b64}\n"),
    )?;
    println!("generated dev public key at {}", pub_path.display());

    Ok(sk)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ── compile handler ───────────────────────────────────────────────────────────

fn run_compile(args: CompileArgs) -> anyhow::Result<()> {
    let trust_store = TrustStore::load_from_dir(&args.trust_root_dir)
        .map_err(|e| anyhow::anyhow!("load trust roots: {e}"))?;
    let verifier = YamlSigilVerifier::new(trust_store);

    let bundle_bytes =
        std::fs::read(&args.bundle_path).map_err(|e| anyhow::anyhow!("read bundle: {e}"))?;

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
    println!(
        "verified  digest={} counter={}",
        outcome.digest_hex, outcome.monotonic_counter
    );

    if !args.verify_only {
        let compiler = Compiler::new(vec![]);
        let parsed = outcome
            .bundle
            .ok_or_else(|| anyhow::anyhow!("bundle did not parse (verification failed earlier)"))?;
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
            println!(
                "projection  kind={} name={} bytes={}",
                s.kind,
                s.name,
                s.bytes.len()
            );
        }
    }
    Ok(())
}

// ── genfixture handler ────────────────────────────────────────────────────────

fn run_genfixture(args: GenfixtureArgs) -> anyhow::Result<()> {
    let base = args
        .base_dir
        .or_else(|| args.template.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));

    let template_bytes = std::fs::read(&args.template)
        .map_err(|e| anyhow::anyhow!("read template {}: {e}", args.template.display()))?;
    let mut payload_str = String::from_utf8(template_bytes)
        .map_err(|e| anyhow::anyhow!("template is not UTF-8: {e}"))?;

    let parsed: serde_yaml::Value = serde_yaml::from_str(&payload_str)
        .map_err(|e| anyhow::anyhow!("template is not valid YAML: {e}"))?;

    if let Some(manifest) = parsed
        .get("manifest")
        .and_then(serde_yaml::Value::as_sequence)
    {
        for entry in manifest {
            let Some(path) = entry.get("path").and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            let abs = base.join(path);
            let member = std::fs::read(&abs)
                .map_err(|e| anyhow::anyhow!("read manifest member {}: {e}", abs.display()))?;
            let digest = sha256_hex(&member);
            if !payload_str.contains("REPLACE_WITH_DIGEST") {
                anyhow::bail!(
                    "manifest entry {path}: template missing `REPLACE_WITH_DIGEST` placeholder"
                );
            }
            payload_str = payload_str.replacen("REPLACE_WITH_DIGEST", &digest, 1);
            println!("manifest  {path}: sha256={digest}");
        }
    }

    let sk = load_or_generate_key(&args.key, args.generate_key, &args.pubkey_out)?;
    let keyid = args.keyid.unwrap_or_else(|| {
        args.key
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string()
    });
    if keyid.is_empty() {
        anyhow::bail!("could not determine keyid; pass --keyid");
    }

    let req = SignRequest {
        payload: payload_str.as_bytes(),
        algorithm: AlgorithmId::Ed25519,
        key: SigilKey::Ed25519(&sk),
        keyid: Some(keyid.as_str()),
        append_missing_final_newline: false,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    let artifact = match yaml_sigil_signing::sign(&req) {
        SignOutcome::Success(s) => s.artifact,
        SignOutcome::Invocation(e) => anyhow::bail!("signing invocation error: {e:?}"),
        SignOutcome::Signer(e) => anyhow::bail!("signing error: {e:?}"),
    };

    if let Some(parent) = args.out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.out, &artifact)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", args.out.display()))?;
    println!("signed bundle written to {}", args.out.display());
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
