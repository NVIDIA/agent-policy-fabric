// SPDX-License-Identifier: Apache-2.0
//! APF Policy Service daemon.
//!
//! Lifecycle:
//!   1. Load and verify the signed bundle; compile projections via registered Projector impls.
//!   2. Serve `PolicyService` (Health, GetDocument, ListDocuments) over UDS.
//!   3. Optionally serve an HTTP surface (health probes, document endpoints, JWKS).

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use apf_bundle::{CounterStore, Ed25519Verifier, TrustStore, verify_bundle};
use apf_compiler::{Compiler, surfaces_to_projections};
use apf_proto::policy_service_v1alpha1::policy_service_server::PolicyServiceServer;
use apf_types::BundleVerifier;
use base64::Engine as _;
use clap::Parser;
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
use apf_policy_service::source::{HttpBundleSource, LocalBundleSource, PolicySource, UpdateStrategy};
use apf_policy_service::surfaces::http::{HttpState, router as http_router};
use apf_policy_service::surfaces::policy_service::PolicyServiceImpl;

const POLICY_SOURCE_LOCAL: &str = "local";
const POLICY_SOURCE_HTTP: &str = "http";
const RESOLVER_PASSTHROUGH: &str = "passthrough";
const RESOLVER_CLAIMS: &str = "claims";

#[derive(Debug, Parser)]
#[command(name = "apf-policy-service", about = "APF Policy Service")]
struct Args {
    /// Path to a TOML configuration file. Values from the file are used as
    /// defaults; CLI arguments and environment variables override them.
    #[arg(long, env = "APF_CONFIG")]
    config: Option<PathBuf>,

    /// Print the resolved configuration as TOML and exit.
    #[arg(long)]
    config_dump: bool,

    /// Path to bind the UDS socket.
    #[arg(long, env = "APF_SOCKET", default_value = "/run/apf/policy-service.sock")]
    socket: PathBuf,

    /// Path to the signed APF policy bundle (local mode).
    #[arg(long, env = "APF_BUNDLE_PATH")]
    bundle_path: Option<PathBuf>,

    /// Directory containing trust-root public keys (`*.pub` files).
    #[arg(long, env = "APF_TRUST_ROOT_DIR", default_value = "./trust-roots")]
    trust_root_dir: PathBuf,

    /// Persistent monotonic-counter high-water-mark file.
    #[arg(long, env = "APF_COUNTER_STORE", default_value = "/var/lib/apf/counter")]
    counter_store: PathBuf,

    /// Ed25519 signing key for document provenance tokens (`ed25519:<base64>`
    /// format). When omitted, an ephemeral key is generated and its public
    /// half is logged for the operator to register in the gateway trust store.
    #[arg(long, env = "APF_DOCUMENT_SIGNING_KEY")]
    document_signing_key: Option<PathBuf>,

    /// Key id stamped on every provenance JWT `kid` header.
    #[arg(long, env = "APF_DOCUMENT_KEY_ID", default_value = "apf-dev")]
    document_key_id: String,

    /// Policy source backend: `local` reads from --bundle-path; `http` fetches
    /// from --bundle-source-url on a poll interval.
    #[arg(long, env = "APF_POLICY_SOURCE", default_value = POLICY_SOURCE_LOCAL)]
    policy_source: String,

    /// Bundle source URL for HTTP mode (may contain `{variant}` for multi-bundle
    /// deployments).
    #[arg(long, env = "APF_BUNDLE_SOURCE_URL")]
    bundle_source_url: Option<String>,

    /// Bundle source auth token. Prefer --bundle-source-token-file to keep the
    /// value out of process arguments.
    #[arg(long, env = "APF_BUNDLE_SOURCE_TOKEN")]
    bundle_source_token: Option<String>,

    /// File containing the bundle source auth token (trimmed).
    #[arg(long, env = "APF_BUNDLE_SOURCE_TOKEN_FILE")]
    bundle_source_token_file: Option<PathBuf>,

    /// Seconds between bundle source polls (HTTP mode).
    #[arg(long, env = "APF_BUNDLE_SOURCE_POLL_INTERVAL", default_value = "30")]
    bundle_source_poll_interval_secs: u64,

    /// Policy name resolver: `passthrough` returns the name unchanged; `claims`
    /// maps caller subjects to policy variants via --claims-config.
    #[arg(long, env = "APF_RESOLVER", default_value = RESOLVER_PASSTHROUGH)]
    resolver: String,

    /// Path to the ClaimsResolver config JSON (used when --resolver=claims).
    #[arg(long, env = "APF_CLAIMS_CONFIG")]
    claims_config: Option<PathBuf>,

    /// TCP address for the optional HTTP surface (health probes, document
    /// endpoints, JWKS). When omitted, only the UDS gRPC surface is started.
    #[arg(long, env = "APF_HTTP_ADDR")]
    http_addr: Option<std::net::SocketAddr>,

    /// Only accept UDS connections from this UID. Defaults to the daemon's
    /// own UID.
    #[arg(long, env = "APF_ALLOWED_UID")]
    allowed_uid: Option<u32>,

    /// Surface IDs this instance is allowed to vend, e.g. `openshell.sandbox.v1`.
    /// Repeatable; also accepts a comma-separated list via `APF_SURFACES`.
    /// When empty, all surfaces the compiler produces are served.
    #[arg(long, env = "APF_SURFACES", value_delimiter = ',')]
    surfaces: Vec<String>,

    /// Seconds a substrate may cache a GetDocument response. Zero = no expiry.
    #[arg(long, env = "APF_DOCUMENT_TTL_SECS", default_value = "0")]
    document_ttl_secs: u64,
}

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

fn resolve_bundle_source_token(args: &Args) -> anyhow::Result<String> {
    if let Some(path) = &args.bundle_source_token_file {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("read --bundle-source-token-file {}: {e}", path.display())
        })?;
        return Ok(raw.trim().to_string());
    }
    if let Some(token) = &args.bundle_source_token {
        warn!("--bundle-source-token is visible in process arguments; prefer --bundle-source-token-file");
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
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut args = Args::parse();

    if let Some(config_path) = &args.config {
        let cfg = config::load(config_path)?;
        // config.apply_to_args signature mirrors the ported RPV field names;
    // args are mapped accordingly.
    let mut _unused_key_id = args.document_key_id.clone();
    let mut _unused_prov_signer = String::new();
    let mut _unused_prov_oidc: Option<String> = None;
    let mut _unused_audit: Option<PathBuf> = None;
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

    let bundle_path = args.bundle_path.clone().ok_or_else(|| {
        anyhow::anyhow!("--bundle-path (or APF_BUNDLE_PATH) is required for local policy source")
    })?;

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
    info!(
        dir = %args.trust_root_dir.display(),
        count = trust_store.len(),
        "loaded bundle trust roots"
    );

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
            "generated ephemeral document signing key; register the printed public key in the gateway trust store"
        );
        DocumentSigner {
            key_id: args.document_key_id.clone(),
            signing_key: sk,
        }
    };

    let mut counter_store = CounterStore::load_or_init(&args.counter_store).map_err(|e| {
        anyhow::anyhow!("load counter store {}: {e}", args.counter_store.display())
    })?;
    info!(
        path = %args.counter_store.display(),
        high_water_mark = counter_store.high_water_mark(),
        "loaded counter store"
    );

    let audit = PolicyServiceAudit::disabled();

    let bundle_bytes = std::fs::read(&bundle_path)
        .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle_path.display()))?;

    let default_verifier = Ed25519Verifier::new(
        trust_store
            .get(&args.document_key_id)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no trust root found for key id '{}'; check --document-key-id",
                    args.document_key_id
                )
            })?,
    );

    let loaded_bundle = load_and_verify_bundle(
        &bundle_bytes,
        &bundle_path,
        &default_verifier,
        &counter_store,
        &audit,
        SystemTime::now(),
    )?;
    counter_store.check_and_advance(loaded_bundle.monotonic_counter)
        .map_err(|e| anyhow::anyhow!("counter advance: {e}"))?;
    info!(
        path = %bundle_path.display(),
        digest = %loaded_bundle.digest_hex,
        counter = loaded_bundle.monotonic_counter,
        "bundle verified and loaded"
    );

    // Compile bundle projections.
    //
    // Projectors are registered here at startup. OpenShellProjector is registered
    // by runtimes/openshell and must be added when that crate is available.
    let compiler = Compiler::new(vec![
        // TODO(P-7): register OpenShellProjector from runtimes/openshell here
    ]);

    let parsed_bundle = apf_bundle::parse_bundle(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("parse verified bundle: {e}"))?;
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
        warn!(
            path = %bundle_path.display(),
            "bundle produced no surface projections; no projectors registered"
        );
    }
    for s in &compiled.surfaces {
        info!(kind = %s.kind, name = %s.name, bytes = s.bytes.len(), "loaded projection");
    }
    let projections = surfaces_to_projections(compiled.surfaces);

    let signer = Arc::new(document_signer);
    let core = Arc::new(PolicyServiceCore {
        bundle: loaded_bundle,
        projections,
        document_signer: Some(Arc::clone(&signer)),
        audit: audit.clone(),
    });

    let mut http_source: Option<Arc<HttpBundleSource>> = None;

    let source: Arc<dyn PolicySource> = if args.policy_source == POLICY_SOURCE_HTTP {
        let url = args.bundle_source_url.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--bundle-source-url required when --policy-source=http")
        })?;
        let token = resolve_bundle_source_token(&args)?;
        let mut src = HttpBundleSource::new(url, &token, compiler)
            .map_err(|e| anyhow::anyhow!("build http bundle source: {e}"))?;
        src.set_counter_store(counter_store);
        src.set_audit(audit.clone());
        src.load_initial().await?;
        let arc = Arc::new(src);
        arc.start_polling(Duration::from_secs(args.bundle_source_poll_interval_secs));
        http_source = Some(Arc::clone(&arc));
        arc
    } else {
        Arc::new(LocalBundleSource::new(core.clone()))
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
    info!(
        socket = %args.socket.display(),
        allowed_uid,
        "policy-service listening"
    );

    let gated = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) => match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed_uid => Some(Ok(stream)),
            Ok(cred) => {
                warn!(
                    peer_uid = cred.uid(),
                    allowed_uid,
                    "rejecting connection: UID mismatch"
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
        if !addr.ip().is_loopback() {
            warn!(%addr, "HTTP surface bound to non-loopback address; no authentication");
        }
        info!(%addr, "policy-service HTTP surface enabled");
        let http_state = HttpState {
            core: Arc::clone(&core),
            source: Arc::clone(&source),
            resolver: Arc::clone(&resolver),
            allowed_kinds: Arc::clone(&allowed_kinds),
            http_source,
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
