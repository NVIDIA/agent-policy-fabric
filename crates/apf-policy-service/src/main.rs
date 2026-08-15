// SPDX-License-Identifier: Apache-2.0
//! APF Policy Service — daemon and operator bootstrap utilities.
//!
//! Subcommands:
//!   serve    Run the policy service daemon
//!   keygen   Generate an Ed25519 signing keypair for document provenance

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use std::time::{Duration, SystemTime};

use apf_bundle::{CounterStore, TrustStore, YamlSigilVerifier, verify_bundle};
use apf_compiler::{Compiler, surfaces_to_projections};
use apf_proto::policy_service_v1alpha1::policy_service_server::PolicyServiceServer;
use apf_types::BundleVerifier;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::net::UnixListener;
use tokio_stream::{StreamExt, wrappers::UnixListenerStream};
use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use apf_policy_service::config;
use apf_policy_service::runtime::audit::{BundleAuditMetadata, PolicyServiceAudit};
use apf_policy_service::runtime::core::{DocumentSigner, LoadedBundle, PolicyServiceCore};
use apf_policy_service::runtime::runtime_context::RuntimeContext;
use apf_policy_service::source::resolver::{ClaimsResolver, PassthroughResolver, PolicyResolver};
use apf_policy_service::source::{HttpBundleSource, LocalBundleSource, PolicySource};
use apf_policy_service::surfaces::http::{HttpState, router as http_router};
use apf_policy_service::surfaces::policy_service::PolicyServiceImpl;

const POLICY_SOURCE_LOCAL: &str = "local";
const POLICY_SOURCE_HTTP: &str = "http";
const RESOLVER_PASSTHROUGH: &str = "passthrough";
const RESOLVER_CLAIMS: &str = "claims";

// ── Top-level CLI ─────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(name = "apf-policy-service", about = "APF Policy Service")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the policy service daemon
    Serve(Box<ServeArgs>),
    /// Generate an Ed25519 signing keypair for document provenance
    Keygen(KeygenArgs),
}

// ── serve ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
struct ServeArgs {
    #[arg(long, env = "APF_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long)]
    config_dump: bool,

    #[arg(
        long,
        env = "APF_SOCKET",
        default_value = "/run/apf/policy-service.sock"
    )]
    socket: PathBuf,

    #[arg(long, env = "APF_BUNDLE_PATH")]
    bundle_path: Option<PathBuf>,

    #[arg(long, env = "APF_TRUST_ROOT_DIR", default_value = "./trust-roots")]
    trust_root_dir: PathBuf,

    #[arg(
        long,
        env = "APF_COUNTER_STORE",
        default_value = "/var/lib/apf/counter"
    )]
    counter_store: PathBuf,

    #[arg(long, env = "APF_DOCUMENT_SIGNING_KEY")]
    document_signing_key: Option<PathBuf>,

    #[arg(long, env = "APF_DOCUMENT_KEY_ID", default_value = "apf-dev")]
    document_key_id: String,

    #[arg(long, env = "APF_POLICY_SOURCE", default_value = POLICY_SOURCE_LOCAL)]
    policy_source: String,

    #[arg(long, env = "APF_BUNDLE_SOURCE_URL")]
    bundle_source_url: Option<String>,

    #[arg(long, env = "APF_BUNDLE_SOURCE_TOKEN")]
    bundle_source_token: Option<String>,

    #[arg(long, env = "APF_BUNDLE_SOURCE_TOKEN_FILE")]
    bundle_source_token_file: Option<PathBuf>,

    #[arg(long, env = "APF_BUNDLE_SOURCE_POLL_INTERVAL", default_value = "30")]
    bundle_source_poll_interval_secs: u64,

    #[arg(long, env = "APF_RESOLVER", default_value = RESOLVER_PASSTHROUGH)]
    resolver: String,

    #[arg(long, env = "APF_CLAIMS_CONFIG")]
    claims_config: Option<PathBuf>,

    #[arg(long, env = "APF_HTTP_ADDR")]
    http_addr: Option<std::net::SocketAddr>,

    /// Bearer token file gating `/v1/documents` and `/v1/refresh`. Required
    /// whenever `--http-addr` is set — the service refuses to start
    /// otherwise. `/health`, `/healthz`, `/readyz`, and
    /// `/.well-known/jwks.json` are always unauthenticated regardless.
    #[arg(long, env = "APF_HTTP_BEARER_TOKEN_FILE")]
    http_bearer_token_file: Option<PathBuf>,

    #[arg(long, env = "APF_ALLOWED_UID")]
    allowed_uid: Option<u32>,

    #[arg(long, env = "APF_SURFACES", value_delimiter = ',')]
    surfaces: Vec<String>,

    #[arg(long, env = "APF_DOCUMENT_TTL_SECS", default_value = "0")]
    document_ttl_secs: u64,
}

// ── keygen ────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
struct KeygenArgs {
    /// Key identifier stamped on every provenance JWT `kid` header.
    #[arg(long, default_value = "apf-dev")]
    key_id: String,

    /// Directory to write `<key-id>.seed` and `<key-id>.pub` into.
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,

    /// Overwrite existing files without prompting.
    #[arg(long)]
    force: bool,
}

// ── shared helpers ────────────────────────────────────────────────────────────

fn load_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
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
        .map_err(|e| anyhow::anyhow!("signing key {}: base64 decode: {e}", path.display()))?;
    if raw.len() != 32 {
        anyhow::bail!(
            "signing key {}: expected 32-byte seed, got {}",
            path.display(),
            raw.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&seed))
}

fn resolve_http_bearer_token(args: &ServeArgs) -> anyhow::Result<Option<Arc<str>>> {
    let Some(path) = &args.http_bearer_token_file else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read --http-bearer-token-file {}: {e}", path.display()))?;
    let token = raw.trim();
    if token.is_empty() {
        anyhow::bail!(
            "--http-bearer-token-file {} is empty",
            path.display()
        );
    }
    Ok(Some(Arc::from(token)))
}

fn resolve_bundle_source_token(args: &ServeArgs) -> anyhow::Result<String> {
    if let Some(path) = &args.bundle_source_token_file {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("read --bundle-source-token-file {}: {e}", path.display())
        })?;
        return Ok(raw.trim().to_string());
    }
    if let Some(token) = &args.bundle_source_token {
        warn!(
            "--bundle-source-token is visible in process arguments; prefer --bundle-source-token-file"
        );
        return Ok(token.clone());
    }
    Ok(String::new())
}

fn load_and_verify_bundle(
    bundle_bytes: &[u8],
    bundle_path: &Path,
    verifier: &dyn BundleVerifier,
    counter_store: &CounterStore,
    audit: &PolicyServiceAudit,
    now: SystemTime,
) -> anyhow::Result<LoadedBundle> {
    let runtime_ctx = RuntimeContext::default();
    let outcome = verify_bundle(
        bundle_bytes,
        bundle_path,
        verifier,
        counter_store,
        now,
        &HashMap::new(),
    );
    let metadata = BundleAuditMetadata::from_counter_and_digest(
        outcome.monotonic_counter,
        &outcome.digest_hex,
    );
    audit
        .emit_verify_bundle(&runtime_ctx, &metadata, &outcome)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !outcome.ok {
        anyhow::bail!(
            "bundle verification failed: {:?}",
            outcome.rejection_reasons
        );
    }
    Ok(LoadedBundle {
        digest_hex: outcome.digest_hex,
        monotonic_counter: outcome.monotonic_counter,
        audit_metadata: metadata,
        bundle: outcome
            .bundle
            .expect("outcome.ok guarantees bundle is present"),
    })
}

// ── keygen handler ────────────────────────────────────────────────────────────

fn run_keygen(args: KeygenArgs) -> anyhow::Result<()> {
    let seed_path = args.output_dir.join(format!("{}.seed", args.key_id));
    let pub_path = args.output_dir.join(format!("{}.pub", args.key_id));

    if !args.force {
        for path in [&seed_path, &pub_path] {
            if path.exists() {
                anyhow::bail!(
                    "{} already exists; use --force to overwrite",
                    path.display()
                );
            }
        }
    }

    std::fs::create_dir_all(&args.output_dir)?;
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let seed_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(vk.to_bytes());

    std::fs::write(&seed_path, format!("ed25519:{seed_b64}\n"))?;
    std::fs::write(&pub_path, format!("ed25519:{pub_b64}\n"))?;

    println!("seed: {}", seed_path.display());
    println!("pub:  {}", pub_path.display());
    println!("public key (for gateway trust store): ed25519:{pub_b64}");
    Ok(())
}

// ── serve handler ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen(args) => run_keygen(args),
        Commands::Serve(mut args) => run_serve(&mut args).await,
    }
}

async fn run_serve(args: &mut ServeArgs) -> anyhow::Result<()> {
    if let Some(config_path) = &args.config.clone() {
        let cfg = config::load(config_path)?;
        let mut _unused_audit: Option<PathBuf> = None;
        let mut _unused_key_id = args.document_key_id.clone();
        let mut _unused_prov_signer = String::new();
        let mut _unused_prov_oidc: Option<String> = None;
        cfg.apply_to_args(
            &mut args.socket,
            &mut args.bundle_path,
            &mut args.trust_root_dir,
            &mut args.counter_store,
            &mut _unused_audit,
            &mut args.allowed_uid,
            &mut args.document_signing_key,
            &mut _unused_key_id,
            &mut args.policy_source,
            &mut args.bundle_source_url,
            &mut args.bundle_source_token,
            &mut args.bundle_source_token_file,
            &mut args.bundle_source_poll_interval_secs,
            &mut args.resolver,
            &mut args.claims_config,
            &mut args.http_addr,
            &mut _unused_prov_signer,
            &mut _unused_prov_oidc,
            &mut args.surfaces,
        );
        info!(path = %config_path.display(), "loaded config");
    }

    let bundle_path = args
        .bundle_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--bundle-path (or APF_BUNDLE_PATH) is required"))?;

    let trust_store = TrustStore::load_from_dir(&args.trust_root_dir).map_err(|e| {
        anyhow::anyhow!(
            "load trust roots from {}: {e}",
            args.trust_root_dir.display()
        )
    })?;
    if trust_store.is_empty() {
        anyhow::bail!(
            "trust-root dir {} contains no `*.pub` keys",
            args.trust_root_dir.display()
        );
    }
    info!(dir = %args.trust_root_dir.display(), count = trust_store.len(), "loaded trust roots");

    let document_signer = if let Some(p) = &args.document_signing_key {
        let sk = load_signing_key(p)?;
        info!(path = %p.display(), key_id = %args.document_key_id, "loaded document signing key");
        DocumentSigner {
            key_id: args.document_key_id.clone(),
            signing_key: sk,
        }
    } else {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        warn!(
            key_id = %args.document_key_id,
            public_key = %format!("ed25519:{pk_b64}"),
            "generated ephemeral signing key; register the public key in the gateway trust store"
        );
        DocumentSigner {
            key_id: args.document_key_id.clone(),
            signing_key: sk,
        }
    };

    let mut counter_store = CounterStore::load_or_init(&args.counter_store)
        .map_err(|e| anyhow::anyhow!("load counter store: {e}"))?;
    info!(
        path = %args.counter_store.display(),
        high_water_mark = counter_store.high_water_mark(),
        "loaded counter store"
    );

    let audit = PolicyServiceAudit::disabled();

    let bundle_bytes = std::fs::read(&bundle_path)
        .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle_path.display()))?;

    let default_verifier = YamlSigilVerifier::new(trust_store.clone());

    let loaded_bundle = load_and_verify_bundle(
        &bundle_bytes,
        &bundle_path,
        &default_verifier,
        &counter_store,
        &audit,
        SystemTime::now(),
    )?;
    counter_store
        .check_and_advance(loaded_bundle.monotonic_counter)
        .map_err(|e| anyhow::anyhow!("counter advance: {e}"))?;
    info!(
        path = %bundle_path.display(),
        digest = %loaded_bundle.digest_hex,
        counter = loaded_bundle.monotonic_counter,
        "bundle verified and loaded"
    );

    let compiler = Compiler::new(vec![Box::new(apf_openshell_projector::OpenShellProjector)]);

    let parsed_bundle = loaded_bundle.bundle.clone();
    let bundle_dir = bundle_path.parent().unwrap_or_else(|| Path::new("."));
    let members = parsed_bundle
        .load_members(bundle_dir)
        .map_err(|e| anyhow::anyhow!("load bundle members: {e}"))?;

    let allowed_kinds: Arc<HashSet<String>> = if args.surfaces.is_empty() {
        Arc::new(HashSet::new())
    } else {
        Arc::new(args.surfaces.iter().cloned().collect())
    };

    let compiled = compiler
        .lower_members(&members, None)
        .map_err(|e| anyhow::anyhow!("compile bundle: {e}"))?;

    if compiled.surfaces.is_empty() {
        warn!(path = %bundle_path.display(), "bundle produced no projections; no projectors registered");
    }
    for s in &compiled.surfaces {
        info!(kind = %s.kind, name = %s.name, bytes = s.bytes.len(), "loaded projection");
    }
    let projections = surfaces_to_projections(compiled.surfaces);

    let signer = Arc::new(document_signer);
    let core = Arc::new(ArcSwap::new(Arc::new(PolicyServiceCore {
        bundle: loaded_bundle,
        projections,
        document_signer: Some(Arc::clone(&signer)),
        audit: audit.clone(),
    })));

    let source: Arc<dyn PolicySource> = if args.policy_source == POLICY_SOURCE_HTTP {
        let url = args.bundle_source_url.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--bundle-source-url required when --policy-source=http")
        })?;
        let token = resolve_bundle_source_token(args)?;
        let mut src = HttpBundleSource::new(url, &token, compiler)
            .map_err(|e| anyhow::anyhow!("build http bundle source: {e}"))?;
        src.set_counter_store(counter_store);
        src.set_audit(audit.clone());
        src.load_initial().await?;
        let arc = Arc::new(src);
        arc.start_polling(Duration::from_secs(args.bundle_source_poll_interval_secs));
        arc
    } else {
        let allowed_surfaces_set: Option<std::collections::BTreeSet<String>> =
            if args.surfaces.is_empty() {
                None
            } else {
                Some(args.surfaces.iter().cloned().collect())
            };
        Arc::new(LocalBundleSource::with_reload(
            Arc::clone(&core),
            YamlSigilVerifier::new(trust_store.clone()),
            CounterStore::load_or_init(&args.counter_store)
                .map_err(|e| anyhow::anyhow!("counter store for reload: {e}"))?,
            Compiler::new(vec![Box::new(apf_openshell_projector::OpenShellProjector)]),
            Some(Arc::clone(&signer)),
            allowed_surfaces_set,
            audit.clone(),
        ))
    };

    let resolver: Arc<dyn PolicyResolver> = match args.resolver.as_str() {
        RESOLVER_PASSTHROUGH => Arc::new(PassthroughResolver),
        RESOLVER_CLAIMS => {
            let config_path = args.claims_config.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--claims-config required when --resolver=claims")
            })?;
            Arc::new(ClaimsResolver::from_config_file(config_path)?)
        }
        other => anyhow::bail!("unknown --resolver: {other}"),
    };

    let policy_svc = PolicyServiceServer::new(PolicyServiceImpl::new(
        Arc::clone(&resolver),
        Arc::clone(&source),
        Arc::clone(&allowed_kinds),
        Some(Arc::clone(&signer)),
        args.document_ttl_secs,
        parsed_bundle.bundle_id.clone(),
    ));

    if args.socket.exists() {
        std::fs::remove_file(&args.socket)?;
    }
    if let Some(parent) = args.socket.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    let listener = UnixListener::bind(&args.socket)?;
    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600))?;
    let allowed_uid = args
        .allowed_uid
        .unwrap_or_else(|| nix::unistd::getuid().as_raw());
    info!(socket = %args.socket.display(), allowed_uid, "policy-service listening");

    let gated = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) => match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed_uid => Some(Ok(stream)),
            Ok(cred) => {
                warn!(
                    peer_uid = cred.uid(),
                    allowed_uid, "rejecting connection: UID mismatch"
                );
                None
            }
            Err(e) => {
                warn!(error = %e, "rejecting connection: peer_cred() failed");
                None
            }
        },
        Err(e) => Some(Err(e)),
    });

    if let Some(addr) = args.http_addr {
        let bearer_token = resolve_http_bearer_token(args)?.ok_or_else(|| {
            anyhow::anyhow!(
                "--http-addr requires --http-bearer-token-file; \
                 /v1/documents and /v1/refresh cannot be exposed unauthenticated"
            )
        })?;
        if !addr.ip().is_loopback() {
            warn!(%addr, "HTTP surface bound to non-loopback address");
        }
        info!(%addr, "HTTP surface enabled");
        let http_state = HttpState {
            core: Arc::clone(&core),
            source: Arc::clone(&source),
            resolver: Arc::clone(&resolver),
            allowed_kinds: Arc::clone(&allowed_kinds),
            bearer_token: Some(bearer_token),
        };
        let app = http_router(http_state);
        let listener_tcp = tokio::net::TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener_tcp, app).await {
                tracing::error!(error = %e, "HTTP surface error");
            }
        });
    }

    Server::builder()
        .add_service(policy_svc)
        .serve_with_incoming(gated)
        .await?;

    Ok(())
}
