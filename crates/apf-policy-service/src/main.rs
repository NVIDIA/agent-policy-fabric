// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! APF Policy Service — daemon and operator bootstrap utilities.
//!
//! Subcommands:
//!   serve    Run the policy service daemon
//!   keygen   Generate an Ed25519 signing keypair for document provenance

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use std::time::Duration;

use apf_bundle::{CounterStore, TrustStore, YamlSigilVerifier};
use apf_compiler::{Compiler, surfaces_to_projections};
use apf_proto::policy_service_v1alpha1::policy_service_server::PolicyServiceServer;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::net::UnixListener;
use tokio::sync::mpsc::error::TrySendError;
use tokio_stream::{StreamExt, wrappers::UnixListenerStream};
use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use apf_policy_service::config;
use apf_policy_service::runtime::audit::{BundleAuditMetadata, PolicyServiceAudit};
use apf_policy_service::runtime::core::{DocumentSigner, LoadedBundle, PolicyServiceCore};
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

    /// Directory for JSONL audit logs; this component writes
    /// `apf-policy-service-audit.jsonl` into it. One file per component, so a
    /// seam moving to its own process later is not a log-path migration.
    /// Required: the service refuses to start unconfigured, or if the
    /// directory cannot be written.
    #[arg(long, env = "APF_AUDIT_LOG_DIR")]
    audit_log_dir: Option<PathBuf>,

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
        anyhow::bail!("--http-bearer-token-file {} is empty", path.display());
    }
    Ok(Some(Arc::from(token)))
}

/// Empty is rejected rather than accepted: the source omits the Authorization
/// header on an empty token, so a failed secret injection would silently fetch
/// policy anonymously. Omitting both flags is how anonymous fetch is requested
/// deliberately, and stays supported.
fn resolve_bundle_source_token(args: &ServeArgs) -> anyhow::Result<String> {
    if let Some(path) = &args.bundle_source_token_file {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("read --bundle-source-token-file {}: {e}", path.display())
        })?;
        let token = raw.trim();
        if token.is_empty() {
            anyhow::bail!(
                "--bundle-source-token-file {} is empty; unset it to fetch anonymously",
                path.display()
            );
        }
        return Ok(token.to_string());
    }
    if let Some(token) = &args.bundle_source_token {
        if token.is_empty() {
            anyhow::bail!("--bundle-source-token is set but empty; unset it to fetch anonymously");
        }
        warn!(
            "--bundle-source-token is visible in process arguments; prefer --bundle-source-token-file"
        );
        return Ok(token.clone());
    }
    Ok(String::new())
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
        let mut _unused_key_id = args.document_key_id.clone();
        let mut _unused_prov_signer = String::new();
        let mut _unused_prov_oidc: Option<String> = None;
        cfg.apply_to_args(
            &mut args.socket,
            &mut args.bundle_path,
            &mut args.trust_root_dir,
            &mut args.counter_store,
            &mut args.audit_log_dir,
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

    // Posture is decided at points spread across startup, but is recorded as
    // one event per boot: split across several records, a missing one cannot be
    // told apart from a control that was fine.
    let mut weakened: Vec<(&str, String)> = Vec::new();

    // argv rather than the parsed value: the flag also accepts an env var,
    // which is not argv-exposed, and a token passed alongside
    // --bundle-source-token-file is still exposed even though it goes unused.
    // Exposure does not depend on the source being HTTP, so this is not gated
    // on it.
    let token_in_argv = std::env::args_os().any(|arg| {
        let arg = arg.to_string_lossy();
        arg == "--bundle-source-token" || arg.starts_with("--bundle-source-token=")
    });
    if token_in_argv {
        weakened.push((
            "startup.token_in_process_args",
            "bundle source token passed in argv; readable by anything that can see /proc"
                .to_owned(),
        ));
    }

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
        weakened.push((
            "startup.ephemeral_signing_key",
            format!(
                "bundles are signed with a generated key ({}) that no gateway trust store holds",
                args.document_key_id
            ),
        ));
        DocumentSigner {
            key_id: args.document_key_id.clone(),
            signing_key: sk,
        }
    };
    let signer = Arc::new(document_signer);

    let mut counter_store = CounterStore::load_or_init(&args.counter_store)
        .map_err(|e| anyhow::anyhow!("load counter store: {e}"))?;
    info!(
        path = %args.counter_store.display(),
        high_water_mark = counter_store.high_water_mark(),
        "loaded counter store"
    );

    // Unconfigured audit is the same failure as a failed audit write, at full
    // scale: the service would enforce policy with no record of what it loaded.
    let audit_log_dir = args.audit_log_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no audit log directory configured; set --audit-log-dir or APF_AUDIT_LOG_DIR \
             (audit_log_dir in the config file)"
        )
    })?;
    let audit = PolicyServiceAudit::to_jsonl_in(audit_log_dir)
        .map_err(|e| anyhow::anyhow!("audit log dir {}: {e}", audit_log_dir.display()))?;

    // Fail-closed, and before the bundle is loaded: this aborts on failure, and
    // every later step leaves something behind — a durably advanced counter
    // that would make the running revision unloadable on restart, a spawned
    // poll task, a bound socket. Nothing here has side effects to undo.
    // Address and token travel together so they cannot diverge: the block that
    // consumes them is ~200 lines below.
    let http_surface: Option<(std::net::SocketAddr, Arc<str>)> = match args.http_addr {
        Some(addr) => Some((
            addr,
            resolve_http_bearer_token(args)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "--http-addr requires --http-bearer-token-file; \
                     /v1/documents and /v1/refresh cannot be exposed unauthenticated"
                )
            })?,
        )),
        None => None,
    };

    // Gated on the source, unlike token_in_process_args above: that one is
    // about exposure, which happens wherever the flag is passed; this is about
    // use, and a local source never reads the token. Exact because
    // resolve_bundle_source_token rejects an empty value, so absent is the only
    // way the Authorization header is omitted.
    if args.policy_source == POLICY_SOURCE_HTTP
        && args.bundle_source_token_file.is_none()
        && args.bundle_source_token.is_none()
    {
        weakened.push((
            "startup.bundle_source_unauthenticated",
            "no bundle source token; policy is fetched without an Authorization header".to_owned(),
        ));
    }

    // to_canonical normalizes v4-mapped v6, so [::ffff:127.0.0.1] is not
    // reported as reachable off-host.
    if let Some((addr, _)) = &http_surface
        && !addr.ip().to_canonical().is_loopback()
    {
        warn!(%addr, "HTTP surface bound to non-loopback address");
        weakened.push((
            "startup.http_bind_non_loopback",
            format!("HTTP surface reachable off-host at {addr}"),
        ));
    }

    audit
        .emit_service_startup(&weakened)
        .map_err(|e| anyhow::anyhow!("audit emission failed for startup posture: {e}"))?;

    let allowed_kinds: Arc<HashSet<String>> = if args.surfaces.is_empty() {
        Arc::new(HashSet::new())
    } else {
        Arc::new(args.surfaces.iter().cloned().collect())
    };

    // Local and HTTP bundle loading are mutually exclusive: each branch
    // reads, verifies, and advances the anti-replay counter only for its
    // own source. Neither branch touches the other's bundle path — in
    // particular, HTTP mode never requires or reads a local bundle file,
    // and never writes the fetched remote bundle to a local path.
    let (source, bundle_id): (Arc<dyn PolicySource>, String) = if args.policy_source
        == POLICY_SOURCE_HTTP
    {
        let url = args.bundle_source_url.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--bundle-source-url required when --policy-source=http")
        })?;
        let token = resolve_bundle_source_token(args)?;
        let compiler = Compiler::new(vec![Box::new(apf_openshell_projector::OpenShellProjector)]);
        let mut src = HttpBundleSource::new(
            url,
            &token,
            compiler,
            Arc::new(YamlSigilVerifier::new(trust_store.clone())),
            counter_store,
        )
        .map_err(|e| anyhow::anyhow!("build http bundle source: {e}"))?;
        src.set_audit(audit.clone());
        // Fails closed: an unreachable, unsigned, expired, incompatible, or
        // replayed remote bundle aborts startup here via `?`.
        src.load_initial().await?;
        let bundle_id = src.bundle_id("").unwrap_or_default();
        info!(url, bundle_id = %bundle_id, "http bundle source: initial bundle verified and loaded");
        let arc = Arc::new(src);
        arc.start_polling(Duration::from_secs(args.bundle_source_poll_interval_secs));
        (arc as Arc<dyn PolicySource>, bundle_id)
    } else {
        let bundle_path = args.bundle_path.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "--bundle-path (or APF_BUNDLE_PATH) is required when --policy-source=local"
            )
        })?;

        let bundle_bytes = std::fs::read(&bundle_path)
            .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle_path.display()))?;

        let default_verifier = YamlSigilVerifier::new(trust_store.clone());
        let compiler = Compiler::new(vec![Box::new(apf_openshell_projector::OpenShellProjector)]);

        let (loaded_bundle, projections) = apf_policy_service::source::BundleLoadContext {
            verifier: &default_verifier,
            counter_store: &mut counter_store,
            audit: &audit,
        }
        .verify_and_advance(&bundle_bytes, &bundle_path, |outcome| {
            let parsed_bundle = outcome
                .bundle
                .clone()
                .expect("outcome.ok guarantees bundle is present");
            let bundle_dir = bundle_path.parent().unwrap_or_else(|| Path::new("."));
            let members = parsed_bundle
                .load_members(bundle_dir)
                .map_err(|e| anyhow::anyhow!("load bundle members: {e}"))?;

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

            let loaded_bundle = LoadedBundle {
                digest_hex: outcome.digest_hex.clone(),
                monotonic_counter: outcome.monotonic_counter,
                audit_metadata: BundleAuditMetadata::from_counter_and_digest(
                    outcome.monotonic_counter,
                    &outcome.digest_hex,
                ),
                bundle: parsed_bundle,
            };
            Ok((loaded_bundle, projections))
        })?;
        // After the counter persisted: recording this inside `on_verified`
        // would log an activation success for a bundle a persist failure then
        // keeps out of force.
        if projections.is_empty()
            && let Err(e) = audit.emit_no_projections(
                &loaded_bundle.digest_hex,
                loaded_bundle.monotonic_counter,
                &loaded_bundle.bundle.bundle_id,
            )
        {
            warn!(error = %e, "audit emission failed for no-projections");
        }

        info!(
            path = %bundle_path.display(),
            digest = %loaded_bundle.digest_hex,
            counter = loaded_bundle.monotonic_counter,
            "bundle verified and loaded"
        );
        let bundle_id = loaded_bundle.bundle.bundle_id.clone();

        let core = Arc::new(ArcSwap::new(Arc::new(PolicyServiceCore {
            bundle: loaded_bundle,
            projections,
            document_signer: Some(Arc::clone(&signer)),
            audit: audit.clone(),
        })));

        let allowed_surfaces_set: Option<std::collections::BTreeSet<String>> =
            if args.surfaces.is_empty() {
                None
            } else {
                Some(args.surfaces.iter().cloned().collect())
            };
        let src = LocalBundleSource::with_reload(
            Arc::clone(&core),
            Arc::new(YamlSigilVerifier::new(trust_store.clone())),
            CounterStore::load_or_init(&args.counter_store)
                .map_err(|e| anyhow::anyhow!("counter store for reload: {e}"))?,
            Compiler::new(vec![Box::new(apf_openshell_projector::OpenShellProjector)]),
            Some(Arc::clone(&signer)),
            allowed_surfaces_set,
            audit.clone(),
        );
        (Arc::new(src) as Arc<dyn PolicySource>, bundle_id)
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
        bundle_id.clone(),
        audit.clone(),
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

    // The socket is the primary data plane, so a refusal here is the same class
    // of event as a rejected bearer token on the HTTP surface: identity, not
    // policy. auth_deny carries no policy or subject identity, which is right —
    // no bundle was consulted, and the peer never authenticated.
    //
    // Written off the accept path. A synchronous JSONL write here would let
    // anything that can connect but fails the UID gate — root, or the owner
    // when --allowed-uid is mis-set — delay every legitimate accept behind its
    // own rejections. The channel is bounded so a flood costs a dropped record
    // rather than unbounded memory.
    let (peer_deny_tx, mut peer_deny_rx) = tokio::sync::mpsc::channel::<(&str, String)>(64);
    let dropped_refusals = Arc::new(AtomicU64::new(0));
    let drain_dropped = Arc::clone(&dropped_refusals);
    let peer_audit = audit.clone();
    let refusal_drain = tokio::spawn(async move {
        // The count is flushed on a timer rather than when the next refusal is
        // drained. Draining is the wrong trigger: a flood that stops leaves the
        // count stranded until some later refusal that may never come, and
        // concealing the gap is precisely what a flood would be for.
        const FLUSH: Duration = Duration::from_secs(5);
        loop {
            let next = tokio::time::timeout(FLUSH, peer_deny_rx.recv()).await;
            let missed = drain_dropped.swap(0, Ordering::Relaxed);
            if missed > 0
                && let Err(e) = peer_audit.emit_auth_deny(
                    "auth.uds_refusals_dropped",
                    format!("{missed} uds peer refusals were not individually recorded"),
                )
            {
                warn!(error = %e, "audit emission failed for dropped uds refusals");
            }
            match next {
                Ok(Some((reason_code, message))) => {
                    if let Err(e) = peer_audit.emit_auth_deny(reason_code, message) {
                        warn!(error = %e, "audit emission failed for uds peer refusal");
                    }
                }
                Ok(None) => break,
                Err(_) => {}
            }
        }
    });

    let gated = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) => match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed_uid => Some(Ok(stream)),
            Ok(cred) => {
                warn!(
                    peer_uid = cred.uid(),
                    allowed_uid, "rejecting connection: UID mismatch"
                );
                if let Err(e) = peer_deny_tx.try_send((
                    "auth.uds_peer_rejected",
                    format!(
                        "peer uid {} does not match the allowed uid {allowed_uid}",
                        cred.uid()
                    ),
                )) {
                    dropped_refusals.fetch_add(1, Ordering::Relaxed);
                    match e {
                        TrySendError::Full(_) => {
                            warn!("uds peer refusal not recorded: audit queue full");
                        }
                        TrySendError::Closed(_) => {
                            warn!("uds peer refusal not recorded: audit drain stopped");
                        }
                    }
                }
                None
            }
            Err(e) => {
                warn!(error = %e, "rejecting connection: peer_cred() failed");
                if let Err(e) = peer_deny_tx.try_send((
                    "auth.uds_peer_cred_failed",
                    "peer credentials could not be read".to_owned(),
                )) {
                    dropped_refusals.fetch_add(1, Ordering::Relaxed);
                    match e {
                        TrySendError::Full(_) => {
                            warn!("uds peer cred failure not recorded: audit queue full");
                        }
                        TrySendError::Closed(_) => {
                            warn!("uds peer cred failure not recorded: audit drain stopped");
                        }
                    }
                }
                None
            }
        },
        Err(e) => Some(Err(e)),
    });

    // Resolved before the posture record: an unauthenticated HTTP surface
    // aborts startup, and a boot that never serves should leave no record.
    if let Some((addr, bearer_token)) = http_surface {
        info!(%addr, "HTTP surface enabled");
        let http_state = HttpState {
            source: Arc::clone(&source),
            resolver: Arc::clone(&resolver),
            allowed_kinds: Arc::clone(&allowed_kinds),
            bearer_token: Some(bearer_token),
            document_signer: Some(Arc::clone(&signer)),
            audit: audit.clone(),
        };
        let app = http_router(http_state);
        let listener_tcp = tokio::net::TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener_tcp, app).await {
                tracing::error!(error = %e, "HTTP surface error");
            }
        });
    }

    let mut refusal_drain = refusal_drain;
    let serve_result = tokio::select! {
        result = Server::builder()
            .add_service(policy_svc)
            .serve_with_incoming(gated) => Some(result),
        // The drain task owns the receiver, so its death closes the channel and
        // every later refusal is dropped — including the count that would
        // disclose the gap. Serving on would be serving unrecorded.
        _ = &mut refusal_drain => None,
    };
    let Some(serve_result) = serve_result else {
        anyhow::bail!("uds refusal audit drain stopped; refusing to serve unrecorded");
    };

    // The listener is gone, so the sender is too and the drain will flush and
    // exit. Awaiting it matters: dropping a JoinHandle detaches rather than
    // aborts, so a shutdown during a flood would take the queued refusals — the
    // record of the flood — down with the runtime.
    match tokio::time::timeout(Duration::from_secs(5), refusal_drain).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(error = %e, "uds refusal audit drain failed; queued refusals unrecorded");
        }
        Err(_) => {
            warn!("uds refusal audit drain did not finish; queued refusals may be unrecorded");
        }
    }
    serve_result?;

    Ok(())
}
