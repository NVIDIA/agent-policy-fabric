// SPDX-License-Identifier: Apache-2.0
//! APF Policy Gateway daemon.
//!
//! Lifecycle:
//!   1. Connect to apf-policy-service; fetch and verify the initial bundle.
//!   2. Build a local Cedar evaluator from the bundle's policy rules.
//!   3. Serve EvaluationService/Evaluate over UDS for in-process callers.
//!   4. Watch for bundle changes; hot-swap the evaluator on update.
//!   5. OpenShell interceptor and middleware are registered by
//!      apf-openshell-interceptor and apf-openshell-middleware adapter crates.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use apf_bundle::{CounterStore, Ed25519Verifier, TrustStore};
use apf_compiler::frontend;
use apf_proto::pdp_v1alpha1::evaluation_service_server::EvaluationServiceServer;
use apf_types::BundleVerifier;
use clap::Parser;
use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use apf_policy_client::PolicyClientHandle;
use apf_policy_gateway::bundle_cache;
use apf_policy_gateway::digest_watcher::{DigestWatcherConfig, spawn_digest_watcher};
use apf_policy_gateway::engine::{build_evaluator, new_evaluator_channel};
use apf_policy_gateway::events;
use apf_policy_gateway::surfaces::evaluation::EvaluationServiceImpl;
use apf_policy_gateway::trust::{JwksWatcherConfig, fetch_ed25519_key_from_jwks, spawn_jwks_watcher};

#[derive(Debug, Parser)]
#[command(name = "apf-policy-gateway", about = "APF Policy Gateway — local Policy Decision Point")]
struct Cli {
    /// UDS socket path for the EvaluationService/Evaluate gRPC surface.
    #[arg(long, env = "APF_GATEWAY_SOCKET", default_value = "/run/apf/policy-gateway.sock")]
    socket: PathBuf,

    /// Only accept UDS connections from this UID. Defaults to the process UID.
    #[arg(long, env = "APF_GATEWAY_ALLOWED_UID")]
    allowed_uid: Option<u32>,

    /// Path to the apf-policy-service UDS socket.
    #[arg(long, env = "APF_POLICY_SERVICE_SOCKET", default_value = "/run/apf/policy-service.sock")]
    policy_service_socket: String,

    /// Surface ID passed to GetDocument when fetching policies.
    #[arg(long, default_value = "openshell.sandbox.v1")]
    document_kind: String,

    /// Document name passed to GetDocument.
    #[arg(long, default_value = "default")]
    document_name: String,

    /// Directory containing trust-root public keys for bundle verification.
    #[arg(long, env = "APF_TRUST_ROOT_DIR", default_value = "./trust-roots")]
    trust_root_dir: PathBuf,

    /// Key ID of the policy-service document signing identity.
    #[arg(long, env = "APF_DOCUMENT_KEY_ID", default_value = "apf-dev")]
    document_key_id: String,

    /// URL of the policy-service JWKS endpoint for provenance token verification.
    #[arg(long, env = "APF_JWKS_URL")]
    jwks_url: Option<String>,

    /// Seconds between JWKS re-fetches. Set to 0 to disable rotation.
    #[arg(long, default_value_t = 60)]
    jwks_refresh_interval_secs: u64,

    /// Persistent monotonic-counter file for bundle anti-rollback.
    #[arg(long, env = "APF_COUNTER_STORE", default_value = "/var/lib/apf/gateway-counter")]
    counter_store: PathBuf,

    /// Seconds between bundle digest polls. Set to 0 to disable refresh.
    #[arg(long, default_value_t = 10)]
    bundle_refresh_interval_secs: u64,

    // ── OpenShell adapter flags ────────────────────────────────────────────────
    // Read by apf-openshell-interceptor and apf-openshell-middleware when registered.

    /// URL of the OpenShell gateway gRPC server to connect to
    /// (e.g. `http://localhost:7001`). Used for outbound calls: provider
    /// profile reconciliation and sandbox policy refresh.
    #[arg(long, env = "APF_OPENSHELL_GATEWAY_URL")]
    openshell_gateway_url: Option<String>,

    /// Address to bind the GatewayInterceptor gRPC surface on
    /// (e.g. `0.0.0.0:18099`). The OpenShell gateway connects here to call
    /// Describe/Evaluate at sandbox admission time.
    #[arg(long, env = "APF_OPENSHELL_INTERCEPTOR_ADDR")]
    openshell_interceptor_addr: Option<String>,

    /// Address to bind the SupervisorMiddleware gRPC surface on
    /// (e.g. `0.0.0.0:9099`). The OpenShell supervisor calls
    /// EvaluateHttpRequest here for per-request enforcement.
    #[arg(long, env = "APF_OPENSHELL_MIDDLEWARE_ADDR")]
    openshell_middleware_addr: Option<String>,
}

fn build_evaluator_from_members(
    members: &apf_bundle::BundleMembers,
) -> anyhow::Result<Arc<dyn apf_policy_eval::Evaluator>> {
    let policy_rules: Vec<_> = members.policy_rules.iter()
        .filter_map(|(_, bytes)| {
            frontend::parse_policy_rule(bytes)
                .ok()
                .and_then(|rule| frontend::parse_policy_rule_doc(&rule).ok())
        })
        .collect();

    let annotators: Vec<_> = frontend::parse_policy_annotators(members).unwrap_or_default();
    let effects: Vec<_>    = frontend::parse_policy_effects(members).unwrap_or_default();
    let findings: Vec<_>   = frontend::parse_policy_findings(members).unwrap_or_default();

    let annotator_docs: Vec<_> = annotators.iter().map(frontend::PolicyAnnotator::to_doc).collect();
    let effect_docs: Vec<_>    = effects.iter().map(|e| frontend::effect_to_doc(e)).collect();
    let finding_docs: Vec<_>   = findings.iter().map(|f| frontend::finding_to_doc(f)).collect();

    build_evaluator(&policy_rules, &annotator_docs, &effect_docs, &finding_docs)
        .map_err(|e| anyhow::anyhow!("build Cedar evaluator: {e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Cli::parse();

    let trust_store = TrustStore::load_from_dir(&args.trust_root_dir)
        .with_context(|| format!("load trust roots from {}", args.trust_root_dir.display()))?;
    if trust_store.is_empty() {
        anyhow::bail!("trust-root dir {} has no `*.pub` keys", args.trust_root_dir.display());
    }
    info!(dir = %args.trust_root_dir.display(), count = trust_store.len(), "loaded trust roots");

    let mut policy_client = PolicyClientHandle::connect(&args.policy_service_socket)
        .await
        .with_context(|| format!("connect to policy-service at {}", args.policy_service_socket))?;

    match policy_client.health().await {
        Ok(h) => info!(state = ?h.state, "policy-service health ok"),
        Err(e) => warn!(error = %e, "policy-service health check failed"),
    }

    let verifying_key: Option<Arc<std::sync::RwLock<ed25519_dalek::VerifyingKey>>> =
        if let Some(ref url) = args.jwks_url {
            info!(url = %url, "fetching Ed25519 verifying key from JWKS");
            let key = fetch_ed25519_key_from_jwks(url).await
                .with_context(|| format!("fetch JWKS from {url}"))?;
            let shared = Arc::new(std::sync::RwLock::new(key));
            if args.jwks_refresh_interval_secs > 0 {
                spawn_jwks_watcher(
                    JwksWatcherConfig {
                        jwks_url: url.clone(),
                        interval: Duration::from_secs(args.jwks_refresh_interval_secs),
                    },
                    Arc::clone(&shared),
                );
            }
            Some(shared)
        } else {
            warn!("--jwks-url not set; provenance token verification disabled");
            None
        };

    let vk = trust_store.get(&args.document_key_id).cloned()
        .ok_or_else(|| anyhow::anyhow!("no trust root for key id '{}'", args.document_key_id))?;
    let bundle_verifier = Ed25519Verifier::new(vk);

    let mut counter_store = CounterStore::load_or_init(&args.counter_store)
        .with_context(|| format!("load counter store {}", args.counter_store.display()))?;

    // Fetch initial bundle and build evaluator.
    let doc = policy_client.get_document(&args.document_kind, &args.document_name, None).await
        .context("fetch initial bundle")?;

    let tmp = std::env::temp_dir().join(format!("apf-gateway-{}.bundle", std::process::id()));
    std::fs::write(&tmp, &doc.body)?;

    let members = bundle_cache::refresh(
        &doc.body,
        &tmp,
        &bundle_verifier as &dyn BundleVerifier,
        &counter_store,
        &HashMap::new(),
    ).context("verify initial bundle")?;

    let _ = std::fs::remove_file(&tmp);

    info!(digest = %doc.digest, "initial bundle loaded and verified");

    let initial = build_evaluator_from_members(&members).context("build initial evaluator")?;
    let (_eval_tx, eval_rx) = new_evaluator_channel(initial);

    // Spawn bundle digest watcher — hot-swaps evaluator on change.
    if args.bundle_refresh_interval_secs > 0 {
        let (event_tx, _) = events::event_channel();
        spawn_digest_watcher(
            DigestWatcherConfig {
                document_kind: args.document_kind.clone(),
                document_name: args.document_name.clone(),
                interval: Duration::from_secs(args.bundle_refresh_interval_secs),
            },
            policy_client.clone(),
            event_tx,
        );
        // TODO(P-7): subscribe to events and rebuild evaluator on BundleChanged
    }

    let eval_svc = EvaluationServiceServer::new(EvaluationServiceImpl {
        evaluator: eval_rx.clone(),
    });

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

    let allowed_uid = args.allowed_uid.unwrap_or_else(|| nix::unistd::getuid().as_raw());
    info!(socket = %args.socket.display(), allowed_uid, "policy-gateway listening");

    let gated = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) => match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed_uid => Some(Ok(stream)),
            Ok(cred) => {
                warn!(peer_uid = cred.uid(), allowed_uid, "rejecting connection: UID mismatch");
                None
            }
            Err(e) => {
                warn!(error = %e, "rejecting connection: peer_cred() failed");
                None
            }
        },
        Err(e) => Some(Err(e)),
    });

    let mut tasks = tokio::task::JoinSet::new();

    // EvaluationService — always started.
    let gated_arc = gated;
    tasks.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(eval_svc)
            .serve_with_incoming(gated_arc)
            .await
            .map_err(|e| anyhow::anyhow!("EvaluationService error: {e}"))
    });

    // OpenShell gateway interceptor — enabled when both --openshell-interceptor-addr
    // (inbound bind) and --openshell-gateway-url (outbound connect) are set.
    if let Some(interceptor_bind) = args.openshell_interceptor_addr.clone() {
        use apf_openshell_interceptor::server::{GatewayInterceptorService, InterceptorConfig};
        use apf_proto::gateway_interceptor_v1::gateway_interceptor_server::GatewayInterceptorServer;

        let verifying_key = verifying_key.ok_or_else(|| {
            anyhow::anyhow!("--jwks-url required when --openshell-interceptor-addr is set")
        })?;

        let config = InterceptorConfig {
            document_kind: args.document_kind.clone(),
            document_name: args.document_name.clone(),
            signing_key_id: args.document_key_id.clone(),
            verifying_key: Arc::clone(&verifying_key),
        };
        let interceptor_svc = GatewayInterceptorService {
            policy_service: policy_client.clone(),
            config,
        };

        let bind_addr = interceptor_bind.parse()
            .context("parse --openshell-interceptor-addr")?;
        info!(
            bind = %interceptor_bind,
            gateway_url = ?args.openshell_gateway_url,
            "OpenShell gateway interceptor enabled"
        );
        tasks.spawn(async move {
            tonic::transport::Server::builder()
                .add_service(GatewayInterceptorServer::new(interceptor_svc))
                .serve(bind_addr)
                .await
                .map_err(|e| anyhow::anyhow!("interceptor server error: {e}"))
        });
    }

    // OpenShell supervisor middleware — optional, enabled by --openshell-middleware-addr.
    if let Some(ref addr) = args.openshell_middleware_addr {
        use apf_openshell_middleware::SupervisorMiddlewareService;
        use apf_proto::supervisor_middleware_v1::supervisor_middleware_server::SupervisorMiddlewareServer;

        let mw_svc = SupervisorMiddlewareService::new(eval_rx.clone());
        info!(addr = %addr, "OpenShell supervisor middleware enabled");
        let addr_parsed = addr.parse().context("parse --openshell-middleware-addr")?;
        tasks.spawn(async move {
            tonic::transport::Server::builder()
                .add_service(SupervisorMiddlewareServer::new(mw_svc))
                .serve(addr_parsed)
                .await
                .map_err(|e| anyhow::anyhow!("middleware server error: {e}"))
        });
    }

    while let Some(res) = tasks.join_next().await {
        res??;
    }

    Ok(())
}
