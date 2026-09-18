// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use apf_compiler::frontend;
use apf_openshell_auth::ExtensionAuthVerifier;
use apf_proto::PolicySet;
use apf_proto::pdp_v1alpha1::evaluation_service_server::EvaluationServiceServer;
use clap::{Args, Parser};
#[cfg(unix)]
use nix::fcntl::OFlag;
use prost::Message as _;
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use apf_openshell_interceptor::audit::InterceptorAudit;
use apf_openshell_middleware::audit::MiddlewareAudit;
use apf_policy_client::PolicyClientHandle;
use apf_policy_eval::ActivePolicy;
use apf_policy_gateway::audit::PolicyGatewayAudit;
use apf_policy_gateway::digest_watcher::{DigestWatcherConfig, spawn_digest_watcher};
use apf_policy_gateway::engine::{build_evaluator, new_evaluator_channel};
use apf_policy_gateway::surfaces::evaluation::EvaluationServiceImpl;
use apf_policy_gateway::trust::{
    JwksWatcherConfig, fetch_ed25519_key_from_jwks, spawn_jwks_watcher,
};
use apf_types::events::{BundleEvent, bundle_event_channel};

const MAX_TLS_CERT_BYTES: usize = 1024 * 1024;
const MAX_TLS_KEY_BYTES: usize = 64 * 1024;

#[derive(Debug, Args, Default)]
struct MiddlewareCli {
    /// Address to bind the SupervisorMiddleware gRPC surface on.
    #[arg(long, env = "APF_OPENSHELL_MIDDLEWARE_ADDR")]
    openshell_middleware_addr: Option<String>,

    /// TOML trust profile used to authenticate OpenShell extension JWTs.
    #[arg(long, env = "APF_OPENSHELL_MIDDLEWARE_AUTH_TRUST_FILE")]
    openshell_middleware_auth_trust_file: Option<PathBuf>,

    /// PEM certificate chain served by the authenticated middleware listener.
    #[arg(long, env = "APF_OPENSHELL_MIDDLEWARE_TLS_CERT_FILE")]
    openshell_middleware_tls_cert_file: Option<PathBuf>,

    /// PEM private key served by the authenticated middleware listener.
    #[arg(long, env = "APF_OPENSHELL_MIDDLEWARE_TLS_KEY_FILE")]
    openshell_middleware_tls_key_file: Option<PathBuf>,

    /// Explicitly disable middleware TLS and caller authentication.
    #[arg(
        long,
        env = "APF_OPENSHELL_MIDDLEWARE_ALLOW_INSECURE_TRANSPORT",
        default_value_t = false
    )]
    openshell_middleware_allow_insecure_transport: bool,
}

impl MiddlewareCli {
    fn resolve(&self) -> Result<Option<SecuredListenerLaunchConfig>, SecuredListenerConfigError> {
        resolve_secured_listener(SecuredListenerInputs {
            surface: "middleware",
            addr_flag: "openshell-middleware-addr",
            insecure_flag: "openshell-middleware-allow-insecure-transport",
            addr: &self.openshell_middleware_addr,
            trust_file: &self.openshell_middleware_auth_trust_file,
            cert_file: &self.openshell_middleware_tls_cert_file,
            key_file: &self.openshell_middleware_tls_key_file,
            allow_insecure_transport: self.openshell_middleware_allow_insecure_transport,
        })
    }
}

#[derive(Debug, Args, Default)]
struct InterceptorCli {
    /// Address to bind the GatewayInterceptor gRPC surface on
    /// (e.g. `0.0.0.0:18099`). The OpenShell gateway connects here to call
    /// Describe/SnapshotProviderProfiles/Evaluate at sandbox admission time.
    #[arg(long, env = "APF_OPENSHELL_INTERCEPTOR_ADDR")]
    openshell_interceptor_addr: Option<String>,

    /// TOML trust profile used to authenticate OpenShell extension JWTs.
    #[arg(long, env = "APF_OPENSHELL_INTERCEPTOR_AUTH_TRUST_FILE")]
    openshell_interceptor_auth_trust_file: Option<PathBuf>,

    /// PEM certificate chain served by the authenticated interceptor listener.
    #[arg(long, env = "APF_OPENSHELL_INTERCEPTOR_TLS_CERT_FILE")]
    openshell_interceptor_tls_cert_file: Option<PathBuf>,

    /// PEM private key served by the authenticated interceptor listener.
    #[arg(long, env = "APF_OPENSHELL_INTERCEPTOR_TLS_KEY_FILE")]
    openshell_interceptor_tls_key_file: Option<PathBuf>,

    /// Explicitly disable interceptor TLS and caller authentication.
    #[arg(
        long,
        env = "APF_OPENSHELL_INTERCEPTOR_ALLOW_INSECURE_TRANSPORT",
        default_value_t = false
    )]
    openshell_interceptor_allow_insecure_transport: bool,
}

impl InterceptorCli {
    fn resolve(&self) -> Result<Option<SecuredListenerLaunchConfig>, SecuredListenerConfigError> {
        resolve_secured_listener(SecuredListenerInputs {
            surface: "interceptor",
            addr_flag: "openshell-interceptor-addr",
            insecure_flag: "openshell-interceptor-allow-insecure-transport",
            addr: &self.openshell_interceptor_addr,
            trust_file: &self.openshell_interceptor_auth_trust_file,
            cert_file: &self.openshell_interceptor_tls_cert_file,
            key_file: &self.openshell_interceptor_tls_key_file,
            allow_insecure_transport: self.openshell_interceptor_allow_insecure_transport,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
enum SecuredListenerConfigError {
    #[error("{surface} security settings require --{addr_flag}")]
    StraySecurityConfig {
        surface: &'static str,
        addr_flag: &'static str,
    },
    #[error("--{insecure_flag} conflicts with TLS or authentication settings")]
    ConflictingSecurityModes { insecure_flag: &'static str },
    #[error(
        "{surface} listener requires the trust file, TLS certificate, and TLS key together, or explicit insecure transport"
    )]
    AuthenticationRequired { surface: &'static str },
}

enum SecuredListenerLaunchConfig {
    Authenticated {
        addr: String,
        trust_file: PathBuf,
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    Insecure {
        addr: String,
    },
}

enum PreparedSecuredServer {
    Authenticated {
        addr: SocketAddr,
        verifier: ExtensionAuthVerifier,
        server: Server,
    },
    Insecure {
        addr: SocketAddr,
    },
}

#[derive(Clone, Copy)]
enum StartupFilePolicy {
    Trust,
    PrivateKey,
}

/// The raw per-surface CLI inputs `resolve_secured_listener` validates. Both
/// `MiddlewareCli` and `InterceptorCli` package their own fields into this
/// shape rather than duplicating the stray-config/conflicting-modes/
/// auth-required validation state machine — see `AGENTS.md`'s "extract on
/// second consumer" rule; that logic is security-relevant and must not drift
/// between the two surfaces.
struct SecuredListenerInputs<'a> {
    surface: &'static str,
    addr_flag: &'static str,
    insecure_flag: &'static str,
    addr: &'a Option<String>,
    trust_file: &'a Option<PathBuf>,
    cert_file: &'a Option<PathBuf>,
    key_file: &'a Option<PathBuf>,
    allow_insecure_transport: bool,
}

fn resolve_secured_listener(
    inputs: SecuredListenerInputs<'_>,
) -> Result<Option<SecuredListenerLaunchConfig>, SecuredListenerConfigError> {
    let configured_inputs = [
        inputs.trust_file.is_some(),
        inputs.cert_file.is_some(),
        inputs.key_file.is_some(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();

    let Some(addr) = inputs.addr else {
        if configured_inputs > 0 || inputs.allow_insecure_transport {
            return Err(SecuredListenerConfigError::StraySecurityConfig {
                surface: inputs.surface,
                addr_flag: inputs.addr_flag,
            });
        }
        return Ok(None);
    };

    if inputs.allow_insecure_transport {
        if configured_inputs > 0 {
            return Err(SecuredListenerConfigError::ConflictingSecurityModes {
                insecure_flag: inputs.insecure_flag,
            });
        }
        return Ok(Some(SecuredListenerLaunchConfig::Insecure {
            addr: addr.clone(),
        }));
    }

    let (Some(trust_file), Some(cert_file), Some(key_file)) =
        (inputs.trust_file, inputs.cert_file, inputs.key_file)
    else {
        return Err(SecuredListenerConfigError::AuthenticationRequired {
            surface: inputs.surface,
        });
    };

    Ok(Some(SecuredListenerLaunchConfig::Authenticated {
        addr: addr.clone(),
        trust_file: trust_file.clone(),
        cert_file: cert_file.clone(),
        key_file: key_file.clone(),
    }))
}

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

    /// Directory for this component's JSONL audit log. Required: a gateway
    /// that enforces policy without recording what it decided has no evidence
    /// trail, so there is no safe default to fall back to. One file per
    /// component, so a later process split is not a log-path migration.
    #[arg(long, env = "APF_AUDIT_LOG_DIR")]
    audit_log_dir: PathBuf,

    // ── OpenShell adapter flags ────────────────────────────────────────────────
    /// URL of the OpenShell gateway gRPC server to connect to
    /// (e.g. `http://localhost:7001`). Used for outbound calls: provider
    /// profile reconciliation and sandbox policy refresh.
    #[arg(long, env = "APF_OPENSHELL_GATEWAY_URL")]
    openshell_gateway_url: Option<String>,

    #[command(flatten)]
    openshell_interceptor: InterceptorCli,

    #[command(flatten)]
    openshell_middleware: MiddlewareCli,
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

async fn read_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
    description: &str,
    policy: StartupFilePolicy,
) -> anyhow::Result<Vec<u8>> {
    let file = open_checked_startup_file(path, description, policy).await?;

    // The checked open binds validation and consumption to one inode. The cap
    // independently bounds a regular file that grows while it is being read.
    let mut bytes = Vec::with_capacity(max_bytes + 1);
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("read {description} at {}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(anyhow::anyhow!(
            "{description} exceeds the {max_bytes}-byte input limit"
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
async fn open_checked_startup_file(
    path: &Path,
    description: &str,
    policy: StartupFilePolicy,
) -> anyhow::Result<tokio::fs::File> {
    use std::os::unix::fs::MetadataExt as _;

    let inspected = tokio::fs::symlink_metadata(path)
        .await
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    validate_startup_file_metadata(&inspected, description, policy)?;

    // O_NOFOLLOW closes the symlink race and O_NONBLOCK prevents a file-type
    // swap to a FIFO from hanging startup before the opened handle is checked.
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits());
    let file = options
        .open(path)
        .await
        .with_context(|| format!("open {description} at {}", path.display()))?;
    let opened = file
        .metadata()
        .await
        .with_context(|| format!("inspect opened {description} at {}", path.display()))?;
    validate_startup_file_metadata(&opened, description, policy)?;
    if inspected.dev() != opened.dev() || inspected.ino() != opened.ino() {
        return Err(anyhow::anyhow!("{description} changed while being opened"));
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_startup_file_metadata(
    metadata: &std::fs::Metadata,
    description: &str,
    policy: StartupFilePolicy,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    // symlink_metadata reports a symlink itself as non-regular, so special
    // files and links are rejected before any potentially blocking open.
    if !metadata.is_file() {
        return Err(anyhow::anyhow!("{description} must be a regular file"));
    }
    let forbidden_mode = match policy {
        StartupFilePolicy::Trust => 0o022,
        StartupFilePolicy::PrivateKey => 0o077,
    };
    if metadata.mode() & forbidden_mode != 0 {
        let requirement = match policy {
            StartupFilePolicy::Trust => "must not be group or world writable",
            StartupFilePolicy::PrivateKey => "must be accessible only by its owner",
        };
        return Err(anyhow::anyhow!("{description} {requirement}"));
    }
    Ok(())
}

#[cfg(not(unix))]
async fn open_checked_startup_file(
    path: &Path,
    description: &str,
    _policy: StartupFilePolicy,
) -> anyhow::Result<tokio::fs::File> {
    let inspected = tokio::fs::symlink_metadata(path)
        .await
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if inspected.file_type().is_symlink() || !inspected.is_file() {
        return Err(anyhow::anyhow!("{description} must be a regular file"));
    }
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {description} at {}", path.display()))?;
    if !file
        .metadata()
        .await
        .with_context(|| format!("inspect opened {description} at {}", path.display()))?
        .is_file()
    {
        return Err(anyhow::anyhow!("{description} must be a regular file"));
    }
    Ok(file)
}

/// Loads the trust profile and TLS identity for one OpenShell extension-auth
/// surface, or resolves an explicit insecure listener. `label` (e.g.
/// `"OpenShell middleware"`) only shapes diagnostic text — both surfaces share
/// identical trust-file and TLS-loading behavior.
async fn prepare_secured_server(
    resolved: Option<SecuredListenerLaunchConfig>,
    addr_flag: &str,
    label: &str,
) -> anyhow::Result<Option<PreparedSecuredServer>> {
    let Some(config) = resolved else {
        return Ok(None);
    };

    match config {
        SecuredListenerLaunchConfig::Insecure { addr } => {
            Ok(Some(PreparedSecuredServer::Insecure {
                addr: addr
                    .parse()
                    .with_context(|| format!("parse --{addr_flag}"))?,
            }))
        }
        SecuredListenerLaunchConfig::Authenticated {
            addr,
            trust_file,
            cert_file,
            key_file,
        } => {
            let verifier = ExtensionAuthVerifier::from_trust_file(&trust_file)
                .await
                .with_context(|| {
                    format!("load {label} trust profile at {}", trust_file.display())
                })?;
            let cert_description = format!("{label} TLS certificate");
            let key_description = format!("{label} TLS private key");
            let (certificate, private_key) = tokio::try_join!(
                read_bounded_regular_file(
                    &cert_file,
                    MAX_TLS_CERT_BYTES,
                    &cert_description,
                    StartupFilePolicy::Trust,
                ),
                read_bounded_regular_file(
                    &key_file,
                    MAX_TLS_KEY_BYTES,
                    &key_description,
                    StartupFilePolicy::PrivateKey,
                ),
            )?;
            let tls = ServerTlsConfig::new().identity(Identity::from_pem(certificate, private_key));
            // Tonic parses the certificate chain and proves the private key
            // matches only while constructing its TLS acceptor. Complete that
            // work before any APF listener can bind or report readiness.
            let server = Server::builder()
                .tls_config(tls)
                .with_context(|| format!("configure {label} server TLS"))?;
            Ok(Some(PreparedSecuredServer::Authenticated {
                addr: addr
                    .parse()
                    .with_context(|| format!("parse --{addr_flag}"))?,
                verifier,
                server,
            }))
        }
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
    let interceptor_server = prepare_secured_server(
        args.openshell_interceptor.resolve()?,
        "openshell-interceptor-addr",
        "OpenShell interceptor",
    )
    .await?;
    let middleware_server = prepare_secured_server(
        args.openshell_middleware.resolve()?,
        "openshell-middleware-addr",
        "OpenShell middleware",
    )
    .await?;

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

    let audit = PolicyGatewayAudit::to_jsonl_in(&args.audit_log_dir)
        .map_err(|e| anyhow::anyhow!("open audit log in {:?}: {e}", args.audit_log_dir))?;

    // Fail-closed, and before the channel exists: a gateway that cannot record
    // which policy it enforces would make every later decision unattributable,
    // and refusing to start is the only outcome that leaves no false trail.
    audit
        .emit_policy_activated("policy.bundle_activated", &doc.digest, doc.version)
        .map_err(|e| anyhow::anyhow!("record initial policy activation: {e}"))?;

    let (eval_tx, eval_rx) = new_evaluator_channel(ActivePolicy {
        evaluator: initial,
        bundle_digest: doc.digest.clone(),
        policy_revision: doc.version,
    });

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
        let swap_audit = audit.clone();
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
                                // The digest of the document this evaluator was
                                // built from, not the one that triggered the
                                // refresh: another change may have landed
                                // between the signal and this fetch.
                                let _ = hot_swap_tx.send(Arc::new(ActivePolicy {
                                    evaluator: new_eval,
                                    bundle_digest: doc.digest.clone(),
                                    policy_revision: doc.version,
                                }));
                                // Halts rather than reverting: the new policy
                                // may be an emergency revocation, so falling
                                // back would re-enable what was just withdrawn.
                                // Requests already decided under it name a
                                // policy no record covers, so there is nothing
                                // left to undo — only somewhere to stop.
                                if let Err(e) = swap_audit.emit_policy_activated(
                                    "policy.bundle_hot_swapped",
                                    &doc.digest,
                                    doc.version,
                                ) {
                                    tracing::error!(
                                        error = %e,
                                        digest = %doc.digest,
                                        "policy hot-swap could not be recorded; halting rather than enforcing unrecorded policy"
                                    );
                                    std::process::exit(1);
                                }
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
        audit: audit.clone(),
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
    // The trust/TLS wrapper owns authentication dispatch and message limits;
    // this runtime owns only listener transport and explicit mode selection.
    // Opened only when a middleware listener is configured: a stale audit file
    // must not fail a startup that would never have served this seam.
    let middleware_audit = || {
        MiddlewareAudit::to_jsonl_in(&args.audit_log_dir).map_err(|e| {
            anyhow::anyhow!("open middleware audit log in {:?}: {e}", args.audit_log_dir)
        })
    };

    if let Some(prepared) = interceptor_server {
        use apf_openshell_interceptor::server::{GatewayInterceptorService, InterceptorConfig};

        let verifying_key = verifying_key.clone().ok_or_else(|| {
            anyhow::anyhow!("--jwks-url required when --openshell-interceptor-addr is set")
        })?;

        let config = InterceptorConfig {
            document_kind: args.document_kind.clone(),
            document_name: args.document_name.clone(),
            signing_key_id: args.document_key_id.clone(),
            verifying_key: Arc::clone(&verifying_key),
            // Its own file: the interceptor is a separate component that
            // happens to share this process today.
            audit: InterceptorAudit::to_jsonl_in(&args.audit_log_dir).map_err(|e| {
                anyhow::anyhow!(
                    "open interceptor audit log in {:?}: {e}",
                    args.audit_log_dir
                )
            })?,
        };

        match prepared {
            PreparedSecuredServer::Authenticated {
                addr,
                verifier,
                mut server,
            } => {
                let audience = verifier.audience().to_string();
                let policy_service = policy_client.clone();
                let service = GatewayInterceptorService::authenticated_server(
                    policy_service,
                    config,
                    verifier,
                );
                info!(
                    %addr,
                    %audience,
                    gateway_url = ?args.openshell_gateway_url,
                    "authenticated OpenShell gateway interceptor enabled"
                );
                tasks.spawn(async move {
                    server
                        .add_service(service)
                        .serve(addr)
                        .await
                        .map_err(|e| anyhow::anyhow!("interceptor server error: {e}"))
                });
            }
            PreparedSecuredServer::Insecure { addr } => {
                warn!(
                    %addr,
                    "INSECURE OpenShell gateway interceptor enabled without TLS or caller authentication"
                );
                let policy_service = policy_client.clone();
                let service = GatewayInterceptorService::insecure_server(policy_service, config);
                tasks.spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(service)
                        .serve(addr)
                        .await
                        .map_err(|e| anyhow::anyhow!("interceptor server error: {e}"))
                });
            }
        }
    }

    // The middleware wrapper owns authentication dispatch and message limits;
    // this runtime owns only listener transport and explicit mode selection.
    if let Some(config) = middleware_server {
        use apf_openshell_middleware::SupervisorMiddlewareService;

        match config {
            PreparedSecuredServer::Authenticated {
                addr,
                verifier,
                mut server,
            } => {
                let audience = verifier.audience().to_string();
                let service = SupervisorMiddlewareService::authenticated_server(
                    eval_rx.clone(),
                    verifier,
                    middleware_audit()?,
                );
                info!(%addr, %audience, "authenticated OpenShell supervisor middleware enabled");
                tasks.spawn(async move {
                    server
                        .add_service(service)
                        .serve(addr)
                        .await
                        .map_err(|e| anyhow::anyhow!("middleware server error: {e}"))
                });
            }
            PreparedSecuredServer::Insecure { addr } => {
                warn!(
                    %addr,
                    "INSECURE OpenShell supervisor middleware enabled without TLS or caller authentication"
                );
                let service = SupervisorMiddlewareService::insecure_server(
                    eval_rx.clone(),
                    middleware_audit()?,
                );
                tasks.spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(service)
                        .serve(addr)
                        .await
                        .map_err(|e| anyhow::anyhow!("middleware server error: {e}"))
                });
            }
        }
    }

    while let Some(res) = tasks.join_next().await {
        res??;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2+Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8=\n-----END PUBLIC KEY-----\n";

    fn middleware_cli(listener: bool, security_mask: u8, allow_insecure: bool) -> MiddlewareCli {
        MiddlewareCli {
            openshell_middleware_addr: listener.then(|| "127.0.0.1:18080".to_string()),
            openshell_middleware_auth_trust_file: (security_mask & 0b001 != 0)
                .then(|| PathBuf::from("trust.toml")),
            openshell_middleware_tls_cert_file: (security_mask & 0b010 != 0)
                .then(|| PathBuf::from("tls-cert.pem.fixture")),
            openshell_middleware_tls_key_file: (security_mask & 0b100 != 0)
                .then(|| PathBuf::from("tls-key.key.fixture")),
            openshell_middleware_allow_insecure_transport: allow_insecure,
        }
    }

    fn interceptor_cli(listener: bool, security_mask: u8, allow_insecure: bool) -> InterceptorCli {
        InterceptorCli {
            openshell_interceptor_addr: listener.then(|| "127.0.0.1:18099".to_string()),
            openshell_interceptor_auth_trust_file: (security_mask & 0b001 != 0)
                .then(|| PathBuf::from("trust.toml")),
            openshell_interceptor_tls_cert_file: (security_mask & 0b010 != 0)
                .then(|| PathBuf::from("tls-cert.pem.fixture")),
            openshell_interceptor_tls_key_file: (security_mask & 0b100 != 0)
                .then(|| PathBuf::from("tls-key.key.fixture")),
            openshell_interceptor_allow_insecure_transport: allow_insecure,
        }
    }

    /// Shared assertions for the stray-config/conflicting-modes/auth-required
    /// state machine, run once per surface via `resolve` so both `MiddlewareCli`
    /// and `InterceptorCli` are checked against identical behavior.
    fn assert_secured_listener_security_group(
        resolve: impl Fn(
            bool,
            u8,
            bool,
        )
            -> Result<Option<SecuredListenerLaunchConfig>, SecuredListenerConfigError>,
    ) {
        assert!(
            resolve(false, 0, false)
                .expect("an absent listener needs no security configuration")
                .is_none()
        );

        for security_mask in 1..=0b111 {
            assert!(matches!(
                resolve(false, security_mask, false),
                Err(SecuredListenerConfigError::StraySecurityConfig { .. })
            ));
        }
        assert!(matches!(
            resolve(false, 0, true),
            Err(SecuredListenerConfigError::StraySecurityConfig { .. })
        ));

        for security_mask in 0..0b111 {
            assert!(matches!(
                resolve(true, security_mask, false),
                Err(SecuredListenerConfigError::AuthenticationRequired { .. })
            ));
        }
        assert!(matches!(
            resolve(true, 0b111, false),
            Ok(Some(SecuredListenerLaunchConfig::Authenticated { .. }))
        ));
        assert!(matches!(
            resolve(true, 0, true),
            Ok(Some(SecuredListenerLaunchConfig::Insecure { .. }))
        ));
        for security_mask in 1..=0b111 {
            assert!(matches!(
                resolve(true, security_mask, true),
                Err(SecuredListenerConfigError::ConflictingSecurityModes { .. })
            ));
        }
    }

    #[test]
    fn middleware_security_group_requires_one_complete_non_conflicting_mode() {
        assert_secured_listener_security_group(|listener, mask, insecure| {
            middleware_cli(listener, mask, insecure).resolve()
        });
    }

    #[test]
    fn interceptor_security_group_requires_one_complete_non_conflicting_mode() {
        assert_secured_listener_security_group(|listener, mask, insecure| {
            interceptor_cli(listener, mask, insecure).resolve()
        });
    }

    #[cfg(unix)]
    fn write_with_mode(path: &Path, contents: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, contents).expect("startup fixture must be written");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("startup fixture permissions must be set");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn startup_files_reject_links_fifos_and_unsafe_modes() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let directory = tempfile::tempdir().expect("temporary directory must be created");
        let certificate = directory.path().join("server-cert.pem.fixture");
        write_with_mode(&certificate, b"certificate fixture", 0o644);
        let bytes = read_bounded_regular_file(
            &certificate,
            128,
            "test certificate",
            StartupFilePolicy::Trust,
        )
        .await
        .expect("secure regular trust material must load");
        assert_eq!(bytes, b"certificate fixture");

        std::fs::set_permissions(&certificate, std::fs::Permissions::from_mode(0o664))
            .expect("certificate permissions must be changed");
        assert!(
            read_bounded_regular_file(
                &certificate,
                128,
                "test certificate",
                StartupFilePolicy::Trust,
            )
            .await
            .is_err()
        );
        std::fs::set_permissions(&certificate, std::fs::Permissions::from_mode(0o644))
            .expect("certificate permissions must be restored");

        let private_key = directory.path().join("server-key.key.fixture");
        write_with_mode(&private_key, b"private key fixture", 0o600);
        read_bounded_regular_file(
            &private_key,
            128,
            "test private key",
            StartupFilePolicy::PrivateKey,
        )
        .await
        .expect("owner-only private key material must load");
        std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o644))
            .expect("private key permissions must be changed");
        assert!(
            read_bounded_regular_file(
                &private_key,
                128,
                "test private key",
                StartupFilePolicy::PrivateKey,
            )
            .await
            .is_err()
        );

        let link = directory.path().join("server-cert-link.pem.fixture");
        symlink(&certificate, &link).expect("certificate symlink fixture must be created");
        assert!(
            read_bounded_regular_file(&link, 128, "test certificate", StartupFilePolicy::Trust,)
                .await
                .is_err()
        );

        let fifo = directory.path().join("server-cert.pipe");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR)
            .expect("certificate FIFO fixture must be created");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            read_bounded_regular_file(&fifo, 128, "test certificate", StartupFilePolicy::Trust),
        )
        .await
        .expect("FIFO rejection must not block startup");
        assert!(result.is_err());
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            read_bounded_regular_file(
                &fifo,
                128,
                "test private key",
                StartupFilePolicy::PrivateKey,
            ),
        )
        .await
        .expect("private-key FIFO rejection must not block startup");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn invalid_tls_identity_fails_during_middleware_preflight() {
        let directory = tempfile::tempdir().expect("temporary directory must be created");
        let trust = directory.path().join("trust.toml");
        let trust_profile = format!(
            r#"issuer = "openshell-gateway:edge/team-a"
audience = "urn:openshell:extension:middleware:apf"
kid = "test-kid"
public_key_pem = '''{TEST_PUBLIC_KEY}'''
max_lifetime_secs = 300
leeway_secs = 30
"#,
        );
        write_with_mode(&trust, trust_profile.as_bytes(), 0o644);
        let certificate = directory.path().join("invalid-cert.pem.fixture");
        let private_key = directory.path().join("invalid-key.key.fixture");
        write_with_mode(&certificate, b"not a certificate", 0o644);
        write_with_mode(&private_key, b"not a private key", 0o600);
        let cli = MiddlewareCli {
            openshell_middleware_addr: Some("127.0.0.1:18080".to_string()),
            openshell_middleware_auth_trust_file: Some(trust),
            openshell_middleware_tls_cert_file: Some(certificate),
            openshell_middleware_tls_key_file: Some(private_key),
            openshell_middleware_allow_insecure_transport: false,
        };

        let error = match prepare_secured_server(
            cli.resolve().expect("fully-configured CLI must resolve"),
            "openshell-middleware-addr",
            "OpenShell middleware",
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("invalid TLS identity must fail middleware preflight"),
        };
        assert!(
            format!("{error:#}").contains("configure OpenShell middleware server TLS"),
            "unexpected preflight error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn invalid_tls_identity_fails_during_interceptor_preflight() {
        let directory = tempfile::tempdir().expect("temporary directory must be created");
        let trust = directory.path().join("trust.toml");
        let trust_profile = format!(
            r#"issuer = "openshell-gateway:edge/team-a"
audience = "urn:openshell:extension:interceptor:apf"
kid = "test-kid"
public_key_pem = '''{TEST_PUBLIC_KEY}'''
max_lifetime_secs = 300
leeway_secs = 30
"#,
        );
        write_with_mode(&trust, trust_profile.as_bytes(), 0o644);
        let certificate = directory.path().join("invalid-cert.pem.fixture");
        let private_key = directory.path().join("invalid-key.key.fixture");
        write_with_mode(&certificate, b"not a certificate", 0o644);
        write_with_mode(&private_key, b"not a private key", 0o600);
        let cli = InterceptorCli {
            openshell_interceptor_addr: Some("127.0.0.1:18099".to_string()),
            openshell_interceptor_auth_trust_file: Some(trust),
            openshell_interceptor_tls_cert_file: Some(certificate),
            openshell_interceptor_tls_key_file: Some(private_key),
            openshell_interceptor_allow_insecure_transport: false,
        };

        let error = match prepare_secured_server(
            cli.resolve().expect("fully-configured CLI must resolve"),
            "openshell-interceptor-addr",
            "OpenShell interceptor",
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("invalid TLS identity must fail interceptor preflight"),
        };
        assert!(
            format!("{error:#}").contains("configure OpenShell interceptor server TLS"),
            "unexpected preflight error: {error:#}"
        );
    }
}
