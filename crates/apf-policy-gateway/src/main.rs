// SPDX-License-Identifier: Apache-2.0
//! APF Policy Gateway daemon.
//!
//! Lifecycle:
//!   1. Connect to apf-policy-service; fetch the initial PolicySet.
//!   2. Build a local Cedar evaluator from the PolicySet.
//!   3. Serve EvaluationService/Evaluate over UDS for in-process callers.
//!   4. Watch for PolicySet digest changes; hot-swap the evaluator on update.
//!   5. OpenShell interceptor and middleware are registered by
//!      apf-openshell-interceptor and apf-openshell-middleware adapter crates.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use apf_compiler::frontend;
use apf_proto::PolicySet;
use apf_proto::pdp_v1alpha1::evaluation_service_server::EvaluationServiceServer;
use clap::Parser;
use prost::Message as _;
use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use apf_policy_client::PolicyClientHandle;
use apf_policy_gateway::digest_watcher::{DigestWatcherConfig, spawn_digest_watcher};
use apf_policy_gateway::engine::{build_evaluator, new_evaluator_channel};
use apf_policy_gateway::surfaces::evaluation::EvaluationServiceImpl;
use apf_policy_gateway::trust::{
    JwksWatcherConfig, fetch_ed25519_key_from_jwks, spawn_jwks_watcher,
};
use apf_types::events::{BundleEvent, bundle_event_channel};

#[derive(Debug, Parser)]
#[command(
    name = "apf-policy-gateway",
    about = "APF Policy Gateway — local Policy Decision Point"
)]
struct Cli {
    /// UDS socket path for the EvaluationService/Evaluate gRPC surface.
    #[arg(
        long,
        env = "APF_GATEWAY_SOCKET",
        default_value = "/run/apf/policy-gateway.sock"
    )]
    socket: PathBuf,

    /// Only accept UDS connections from this UID. Defaults to the process UID.
    #[arg(long, env = "APF_GATEWAY_ALLOWED_UID")]
    allowed_uid: Option<u32>,

    /// Path to the apf-policy-service UDS socket.
    #[arg(
        long,
        env = "APF_POLICY_SERVICE_SOCKET",
        default_value = "/run/apf/policy-service.sock"
    )]
    policy_service_socket: String,

    /// Surface ID passed to GetDocument when fetching sandbox policy for interceptor.
    #[arg(long, default_value = "openshell.sandbox.v1")]
    document_kind: String,

    /// Document name passed to GetDocument for sandbox policy.
    #[arg(long, default_value = "default")]
    document_name: String,

    /// Key ID of the policy-service document signing identity.
    #[arg(long, env = "APF_DOCUMENT_KEY_ID", default_value = "apf-dev")]
    document_key_id: String,

    /// URL of the policy-service JWKS endpoint for provenance token verification.
    #[arg(long, env = "APF_JWKS_URL")]
    jwks_url: Option<String>,

    /// Seconds between JWKS re-fetches. Set to 0 to disable rotation.
    #[arg(long, default_value_t = 60)]
    jwks_refresh_interval_secs: u64,

    /// Seconds between PolicySet digest polls. Set to 0 to disable refresh.
    #[arg(long, default_value_t = 10)]
    bundle_refresh_interval_secs: u64,

    // ── OpenShell adapter flags ────────────────────────────────────────────────
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

fn build_evaluator_from_policy_set(
    ps: &PolicySet,
) -> anyhow::Result<Arc<dyn apf_policy_eval::Evaluator>> {
    let policy_rules: Vec<_> = ps
        .rules
        .iter()
        .filter_map(|rule| frontend::parse_policy_rule_doc(rule).ok())
        .collect();

    let annotator_docs: Vec<_> = ps.annotators.iter().map(policy_annotator_to_doc).collect();

    let effect_docs: Vec<_> = ps.effects.iter().map(frontend::effect_to_doc).collect();
    let finding_docs: Vec<_> = ps.findings.iter().map(frontend::finding_to_doc).collect();

    build_evaluator(&policy_rules, &annotator_docs, &effect_docs, &finding_docs)
        .map_err(|e| anyhow::anyhow!("build Cedar evaluator: {e}"))
}

fn policy_annotator_to_doc(
    a: &apf_proto::ir::PolicyAnnotator,
) -> apf_policy_eval::PolicyAnnotatorDoc {
    use apf_proto::ir::{AnnotationOp, AnnotationOutput, SetTrueIf, SetValueFrom};

    let annotations = a
        .spec
        .as_ref()
        .map(|s| {
            s.annotations
                .iter()
                .map(|spec| {
                    let output = match AnnotationOutput::try_from(spec.output).unwrap_or_default() {
                        AnnotationOutput::Bool | AnnotationOutput::Unspecified => {
                            apf_policy_eval::AnnotationOutput::Bool
                        }
                        AnnotationOutput::String => apf_policy_eval::AnnotationOutput::String,
                        AnnotationOutput::Integer => apf_policy_eval::AnnotationOutput::Integer,
                    };
                    let set_true_if = match SetTrueIf::try_from(spec.set_true_if)
                        .unwrap_or_default()
                    {
                        SetTrueIf::Unspecified | SetTrueIf::Any => apf_policy_eval::SetTrueIf::Any,
                        SetTrueIf::All => apf_policy_eval::SetTrueIf::All,
                    };
                    let set_value_from =
                        match SetValueFrom::try_from(spec.set_value_from).unwrap_or_default() {
                            SetValueFrom::Unspecified | SetValueFrom::FirstMatch => {
                                apf_policy_eval::SetValueFrom::FirstMatch
                            }
                        };
                    let rules = spec
                        .rules
                        .iter()
                        .map(|r| {
                            let op = match AnnotationOp::try_from(r.op).unwrap_or_default() {
                                AnnotationOp::Unspecified | AnnotationOp::RegexMatch => {
                                    apf_policy_eval::AnnotationOp::RegexMatch
                                }
                                AnnotationOp::Equals => apf_policy_eval::AnnotationOp::Equals,
                                AnnotationOp::Endswith => apf_policy_eval::AnnotationOp::EndsWith,
                                AnnotationOp::Startswith => {
                                    apf_policy_eval::AnnotationOp::StartsWith
                                }
                                AnnotationOp::Contains => apf_policy_eval::AnnotationOp::Contains,
                                AnnotationOp::Length => apf_policy_eval::AnnotationOp::Length,
                                AnnotationOp::Gte => apf_policy_eval::AnnotationOp::Gte,
                                AnnotationOp::Lte => apf_policy_eval::AnnotationOp::Lte,
                                AnnotationOp::Passthrough => {
                                    apf_policy_eval::AnnotationOp::Passthrough
                                }
                            };
                            apf_policy_eval::AnnotationRule {
                                field: r.field.clone(),
                                op,
                                pattern: r.pattern.clone(),
                                value: r.value.clone(),
                                suffix: r.suffix.clone(),
                                prefix: r.prefix.clone(),
                                substring: r.substring.clone(),
                                threshold: r.threshold,
                            }
                        })
                        .collect();
                    apf_policy_eval::AnnotationSpec {
                        name: spec.name.clone(),
                        output,
                        set_true_if,
                        set_value_from,
                        rules,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    apf_policy_eval::PolicyAnnotatorDoc {
        name: a
            .metadata
            .as_ref()
            .map(|m| m.name.clone())
            .unwrap_or_default(),
        annotations,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Cli::parse();

    let mut policy_client = PolicyClientHandle::connect(&args.policy_service_socket)
        .await
        .with_context(|| {
            format!(
                "connect to policy-service at {}",
                args.policy_service_socket
            )
        })?;

    match policy_client.health().await {
        Ok(h) => info!(state = ?h.state, "policy-service health ok"),
        Err(e) => warn!(error = %e, "policy-service health check failed"),
    }

    let verifying_key: Option<Arc<std::sync::RwLock<ed25519_dalek::VerifyingKey>>> =
        if let Some(ref url) = args.jwks_url {
            info!(url = %url, "fetching Ed25519 verifying key from JWKS");
            let key = fetch_ed25519_key_from_jwks(url)
                .await
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

    // Fetch the PolicySet and build the initial Cedar evaluator.
    let doc = policy_client
        .get_document("apf.policy.v1", "default", None)
        .await
        .context("fetch apf.policy.v1 PolicySet")?;
    let policy_set = PolicySet::decode(doc.body.as_slice()).context("decode PolicySet")?;
    let initial =
        build_evaluator_from_policy_set(&policy_set).context("build initial Cedar evaluator")?;
    info!(digest = %doc.digest, "initial PolicySet loaded");

    let (eval_tx, eval_rx) = new_evaluator_channel(initial);

    // broadcast::Sender — all subscribers share one digest change signal.
    let (event_tx, event_rx_pdp) = bundle_event_channel();

    // Digest watcher polls apf.policy.v1/default and emits BundleChanged on change.
    if args.bundle_refresh_interval_secs > 0 {
        spawn_digest_watcher(
            DigestWatcherConfig {
                document_kind: "apf.policy.v1".to_string(),
                document_name: "default".to_string(),
                interval: Duration::from_secs(args.bundle_refresh_interval_secs),
            },
            policy_client.clone(),
            event_tx.clone(),
        );

        // Subscriber 1: Cedar evaluator hot-swap.
        let mut hot_swap_client = policy_client.clone();
        let hot_swap_tx = eval_tx.clone();
        let mut hot_swap_rx = event_rx_pdp;
        tokio::spawn(async move {
            while let Ok(BundleEvent::BundleChanged { digest, .. }) = hot_swap_rx.recv().await {
                info!(%digest, "PolicySet changed — rebuilding Cedar evaluator");
                match hot_swap_client
                    .get_document("apf.policy.v1", "default", None)
                    .await
                {
                    Ok(doc) => match PolicySet::decode(doc.body.as_slice()) {
                        Ok(ps) => match build_evaluator_from_policy_set(&ps) {
                            Ok(new_eval) => {
                                let _ = hot_swap_tx.send(new_eval);
                                info!("Cedar evaluator hot-swapped");
                            }
                            Err(e) => warn!(error = %e, "evaluator rebuild failed"),
                        },
                        Err(e) => warn!(error = %e, "PolicySet decode failed on hot-swap"),
                    },
                    Err(e) => warn!(error = %e, "get_document failed on hot-swap"),
                }
            }
        });

        // Subscriber 2: provider profile reconciler.
        if let Some(ref gw_url) = args.openshell_gateway_url {
            apf_openshell_interceptor::reconciler::spawn_profile_reconciler(
                gw_url.clone(),
                None,
                policy_client.clone(),
                event_tx.subscribe(),
            );
        }

        // Subscriber 3: sandbox policy refresher.
        if let (Some(gw_url), Some(key)) = (&args.openshell_gateway_url, &verifying_key) {
            use apf_openshell_interceptor::refresher::{RefresherConfig, spawn_policy_refresher};
            spawn_policy_refresher(
                RefresherConfig {
                    gateway_endpoint: gw_url.clone(),
                    gateway_tls: None,
                    verifying_key: Arc::clone(key),
                },
                event_tx.subscribe(),
            );
        }
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

    let allowed_uid = args
        .allowed_uid
        .unwrap_or_else(|| nix::unistd::getuid().as_raw());
    info!(socket = %args.socket.display(), allowed_uid, "policy-gateway listening");

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

    let mut tasks = tokio::task::JoinSet::new();

    tasks.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(eval_svc)
            .serve_with_incoming(gated)
            .await
            .map_err(|e| anyhow::anyhow!("EvaluationService error: {e}"))
    });

    // OpenShell gateway interceptor — enabled when --openshell-interceptor-addr is set.
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

        let bind_addr = interceptor_bind
            .parse()
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

    // OpenShell supervisor middleware — enabled by --openshell-middleware-addr.
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
