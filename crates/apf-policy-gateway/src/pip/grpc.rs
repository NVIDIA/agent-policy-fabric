// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `PolicyInformationService` contract over HTTPS with mutual TLS or over
//! a Unix domain socket with peer-UID verification.
//!
//! Both constructors validate their endpoint when the gateway starts. The
//! channel itself opens on the first lookup and is dropped whenever a call
//! fails at the transport level, so the next lookup reconnects.

use std::fmt;
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use apf_proto::pip_v1alpha1::policy_information_service_client::PolicyInformationServiceClient;
use apf_proto::pip_v1alpha1::{GetAttributesRequest, GetAttributesResponse};
use nix::fcntl::{AtFlags, OFlag};
use nix::unistd::AccessFlags;
use prost::Message as _;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore};
use tonic::Request;
use tonic::codegen::http::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use super::config::{ConfigError, TlsConfig, is_loopback_host};
use super::provider::{
    Lookup, LookupFuture, MAX_MESSAGE_BYTES, ProviderError, ProviderTransport, validate_response,
};

/// Size cap on each TLS material file.
pub const MAX_PEM_BYTES: usize = 64 * 1024;

/// Authority of a channel that connects through a custom connector; the
/// connector ignores it.
const UNIX_AUTHORITY: &str = "http://[::]:50051";

/// gRPC client for one registered provider.
pub struct GrpcTransport {
    target: Target,
    channel: Mutex<Option<Channel>>,
    permits: Semaphore,
    max_in_flight: usize,
}

enum Target {
    Unix { socket: PathBuf, peer_uid: u32 },
    Http { endpoint: Box<Endpoint> },
}

impl fmt::Debug for GrpcTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("GrpcTransport");
        match &self.target {
            Target::Unix { socket, peer_uid } => {
                debug.field("socket", socket).field("peer_uid", peer_uid);
            }
            Target::Http { endpoint } => {
                debug.field("uri", &endpoint.uri().to_string());
            }
        }
        debug
            .field("max_in_flight", &self.max_in_flight)
            .finish_non_exhaustive()
    }
}

impl GrpcTransport {
    /// Connect lazily over a Unix domain socket owned by `peer_uid`.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket fails the ownership or connectability
    /// checks.
    pub fn unix(socket: PathBuf, peer_uid: u32, max_in_flight: usize) -> Result<Self, ConfigError> {
        check_endpoint(&socket, peer_uid).map_err(|error| {
            ConfigError::Invalid(format!("provider socket {}: {error}", socket.display()))
        })?;
        Self::with_target(Target::Unix { socket, peer_uid }, max_in_flight)
    }

    /// Connect lazily over HTTPS with the gateway's client identity, or over
    /// plain HTTP for a loopback host.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL or the TLS material is unusable.
    pub fn https(
        url: &str,
        tls: Option<&TlsConfig>,
        max_in_flight: usize,
    ) -> Result<Self, ConfigError> {
        let parsed = url::Url::parse(url)
            .map_err(|error| ConfigError::Invalid(format!("invalid provider URL: {error}")))?;
        let host = match parsed.host() {
            Some(url::Host::Domain(domain)) => domain.to_owned(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => {
                return Err(ConfigError::Invalid(
                    "provider URL must name a host".to_owned(),
                ));
            }
        };
        let mut endpoint = Endpoint::from_shared(url.to_owned())
            .map_err(|error| ConfigError::Invalid(format!("invalid provider URL: {error}")))?;
        match (parsed.scheme(), tls) {
            ("https", Some(tls)) => {
                let ca = read_checked_file(&tls.ca_file, false, MAX_PEM_BYTES)
                    .map_err(|reason| ConfigError::Invalid(format!("tls.ca_file: {reason}")))?;
                let cert = read_checked_file(&tls.client_cert_file, false, MAX_PEM_BYTES).map_err(
                    |reason| ConfigError::Invalid(format!("tls.client_cert_file: {reason}")),
                )?;
                let key = read_checked_file(&tls.client_key_file, true, MAX_PEM_BYTES).map_err(
                    |reason| ConfigError::Invalid(format!("tls.client_key_file: {reason}")),
                )?;
                let tls_config = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(cert, key))
                    .domain_name(host);
                endpoint = endpoint.tls_config(tls_config).map_err(|error| {
                    ConfigError::Invalid(format!("provider TLS material rejected: {error}"))
                })?;
            }
            ("https", None) => {
                return Err(ConfigError::Invalid(
                    "https endpoints require tls material".to_owned(),
                ));
            }
            ("http", None) if is_loopback_host(&parsed) => {}
            ("http", None) => {
                return Err(ConfigError::Invalid(
                    "plain http endpoints are allowed for loopback hosts only".to_owned(),
                ));
            }
            ("http", Some(_)) => {
                return Err(ConfigError::Invalid(
                    "tls is only valid for https endpoints".to_owned(),
                ));
            }
            (other, _) => {
                return Err(ConfigError::Invalid(format!(
                    "unsupported endpoint scheme '{other}'"
                )));
            }
        }
        Self::with_target(
            Target::Http {
                endpoint: Box::new(endpoint),
            },
            max_in_flight,
        )
    }

    fn with_target(target: Target, max_in_flight: usize) -> Result<Self, ConfigError> {
        if max_in_flight == 0 {
            return Err(ConfigError::Invalid(
                "max_in_flight must be at least 1".to_owned(),
            ));
        }
        Ok(Self {
            target,
            channel: Mutex::new(None),
            permits: Semaphore::new(max_in_flight),
            max_in_flight,
        })
    }

    /// In-flight limit for this provider.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// The cached channel, connecting first when there is none.
    async fn channel(&self) -> Result<Channel, ProviderError> {
        let mut cached = self.channel.lock().await;
        if let Some(channel) = cached.as_ref() {
            return Ok(channel.clone());
        }
        let channel = match &self.target {
            Target::Unix { socket, peer_uid } => {
                check_endpoint(socket, *peer_uid)?;
                connect_unix(socket.clone(), *peer_uid)
                    .await
                    .map_err(|error| connect_error(&error))?
            }
            Target::Http { endpoint } => endpoint
                .connect()
                .await
                .map_err(|error| ProviderError::Unavailable(error.to_string()))?,
        };
        *cached = Some(channel.clone());
        Ok(channel)
    }

    async fn reset_channel(&self) {
        *self.channel.lock().await = None;
    }

    async fn call(
        &self,
        request: GetAttributesRequest,
        budget: Duration,
    ) -> Result<GetAttributesResponse, ProviderError> {
        let channel = self.channel().await?;
        let mut client = PolicyInformationServiceClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let mut request = Request::new(request);
        request.set_timeout(budget);
        client
            .get_attributes(request)
            .await
            .map(tonic::Response::into_inner)
            .map_err(|status| match status.code() {
                // A tonic server reports an expired grpc-timeout as CANCELLED.
                tonic::Code::Cancelled => ProviderError::Timeout,
                // The client decoder reports a frame over the message cap as
                // OUT_OF_RANGE.
                tonic::Code::OutOfRange => {
                    ProviderError::InvalidOutput(status.message().to_owned())
                }
                _ => ProviderError::from_status(&status),
            })
    }
}

impl ProviderTransport for GrpcTransport {
    fn lookup<'a>(&'a self, lookup: Lookup, budget: Duration) -> LookupFuture<'a> {
        Box::pin(async move {
            let _permit = self
                .permits
                .try_acquire()
                .map_err(|_| ProviderError::Capacity)?;
            let request = GetAttributesRequest {
                subject: Some(lookup.subject),
                domains: vec![lookup.domain.clone()],
                correlation_id: lookup.correlation_id,
            };
            if request.encoded_len() > MAX_MESSAGE_BYTES {
                return Err(ProviderError::InvalidInput(
                    "evaluation subject exceeds the message size cap".to_owned(),
                ));
            }
            let response = match tokio::time::timeout(budget, self.call(request, budget)).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    if matches!(
                        error,
                        ProviderError::Timeout | ProviderError::Unavailable(_)
                    ) {
                        self.reset_channel().await;
                    }
                    return Err(error);
                }
                Err(_elapsed) => {
                    self.reset_channel().await;
                    return Err(ProviderError::Timeout);
                }
            };
            validate_response(&response, &lookup.domain)
        })
    }
}

/// Open a channel over the socket, refusing a peer that does not run as
/// `peer_uid`.
async fn connect_unix(socket: PathBuf, peer_uid: u32) -> Result<Channel, tonic::transport::Error> {
    Endpoint::from_static(UNIX_AUTHORITY)
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let stream = UnixStream::connect(&socket).await?;
                verify_peer(&stream, peer_uid)?;
                Ok::<_, io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
}

/// The connected peer runs as a UID other than the registered one.
#[derive(Debug)]
struct PeerUidMismatch {
    expected: u32,
    actual: u32,
}

impl fmt::Display for PeerUidMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "provider socket peer runs as uid {}, expected {}",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for PeerUidMismatch {}

fn verify_peer(stream: &UnixStream, peer_uid: u32) -> io::Result<()> {
    let actual = stream.peer_cred()?.uid();
    if actual != peer_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            PeerUidMismatch {
                expected: peer_uid,
                actual,
            },
        ));
    }
    Ok(())
}

/// Map a connection failure onto the error taxonomy: a peer-UID mismatch is
/// an authorization failure, anything else means the provider is unreachable.
fn connect_error(error: &tonic::transport::Error) -> ProviderError {
    classify_error_chain(error)
}

fn classify_error_chain(error: &(dyn std::error::Error + 'static)) -> ProviderError {
    let mut current = Some(error);
    while let Some(link) = current {
        if link.is::<PeerUidMismatch>() {
            return ProviderError::Unauthorized(link.to_string());
        }
        // An io::Error's source() skips the error it wraps, so descend into
        // that error directly.
        current = match link.downcast_ref::<io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => link.source(),
        };
    }
    ProviderError::Unavailable(error.to_string())
}

/// Check that a provider socket is owned by `peer_uid`, not accessible by
/// other users, connectable by the gateway's user, and reached through
/// directories owned by root, the current user or `peer_uid` that are not
/// writable by others.
///
/// # Errors
///
/// Returns the reason the socket cannot be trusted or reached.
pub fn check_endpoint(path: &Path, peer_uid: u32) -> Result<(), ProviderError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ProviderError::Unavailable(format!(
            "inspect provider socket {}: {error}",
            path.display()
        ))
    })?;
    socket_rule(
        metadata.file_type().is_socket(),
        metadata.uid(),
        metadata.mode(),
        peer_uid,
    )?;
    // Connecting needs write permission on the socket; the probe uses the
    // effective ids the connect will use.
    nix::unistd::faccessat(None, path, AccessFlags::W_OK, AtFlags::AT_EACCESS).map_err(
        |error| {
            ProviderError::Misconfigured(format!(
                "provider socket {} is not connectable by the gateway's user: {error}",
                path.display()
            ))
        },
    )?;
    let current_uid = nix::unistd::geteuid().as_raw();
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).map_err(|error| {
            ProviderError::Misconfigured(format!("inspect {}: {error}", ancestor.display()))
        })?;
        ancestor_rule(
            metadata.is_dir(),
            metadata.uid(),
            metadata.mode(),
            current_uid,
            peer_uid,
        )
        .map_err(|reason| {
            ProviderError::Misconfigured(format!("{} {reason}", ancestor.display()))
        })?;
    }
    Ok(())
}

/// Rules for the socket inode itself.
fn socket_rule(is_socket: bool, uid: u32, mode: u32, peer_uid: u32) -> Result<(), ProviderError> {
    if !is_socket {
        return Err(ProviderError::Misconfigured(
            "provider endpoint is not a socket".to_owned(),
        ));
    }
    if uid != peer_uid {
        return Err(ProviderError::Unauthorized(format!(
            "provider socket is owned by uid {uid}, expected {peer_uid}"
        )));
    }
    if mode & 0o007 != 0 {
        return Err(ProviderError::Misconfigured(
            "provider socket must not be accessible by other users".to_owned(),
        ));
    }
    Ok(())
}

/// Rules for each directory on the way to the socket.
fn ancestor_rule(
    is_dir: bool,
    uid: u32,
    mode: u32,
    current_uid: u32,
    peer_uid: u32,
) -> Result<(), String> {
    if !is_dir {
        return Err("is not a directory".to_owned());
    }
    if uid != 0 && uid != current_uid && uid != peer_uid {
        return Err(format!("is owned by uid {uid}"));
    }
    let sticky_root = uid == 0 && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !sticky_root {
        return Err("is writable by other users".to_owned());
    }
    Ok(())
}

/// Read a TLS material file through a checked open: a regular file that is
/// not a symlink, not writable by others, owner-only when `owner_only`, and
/// no larger than `max_bytes`. The opened inode is validated again so the
/// bytes read are the bytes inspected.
fn read_checked_file(path: &Path, owner_only: bool, max_bytes: usize) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let inspected = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    check_file_metadata(&inspected, owner_only)?;
    let flags = OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits())
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect opened {}: {error}", path.display()))?;
    check_file_metadata(&opened, owner_only)?;
    if (inspected.dev(), inspected.ino()) != (opened.dev(), opened.ino()) {
        return Err(format!("{} changed while being opened", path.display()));
    }
    let mut bytes = Vec::new();
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "{} exceeds the {max_bytes}-byte limit",
            path.display()
        ));
    }
    Ok(bytes)
}

fn check_file_metadata(metadata: &std::fs::Metadata, owner_only: bool) -> Result<(), String> {
    if !metadata.is_file() {
        return Err("must be a regular file".to_owned());
    }
    if owner_only {
        if metadata.mode() & 0o077 != 0 {
            return Err("must be accessible only by its owner".to_owned());
        }
    } else if metadata.mode() & 0o022 != 0 {
        return Err("must not be group or world writable".to_owned());
    }
    Ok(())
}

/// In-process providers for transport and enricher tests.
#[cfg(test)]
pub(crate) mod testing {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use apf_proto::json::json_to_proto_value;
    use apf_proto::pip_v1alpha1::policy_information_service_server::{
        PolicyInformationService, PolicyInformationServiceServer,
    };
    use apf_proto::pip_v1alpha1::{AttributeStatus, GetAttributesRequest, GetAttributesResponse};
    use serde_json::Value;
    use tonic::{Request, Response, Status};

    use crate::pip::provider::authorize_peer;

    /// Answers every lookup with a configurable reply after a configurable
    /// delay and records what it was asked.
    #[derive(Clone)]
    pub(crate) struct FakeProvider {
        reply: Arc<Mutex<Result<GetAttributesResponse, Status>>>,
        requests: Arc<Mutex<Vec<GetAttributesRequest>>>,
        delay_ms: Arc<AtomicU64>,
        /// Peer UID the provider requires on a Unix socket, if any.
        peer_uid: Option<u32>,
    }

    impl FakeProvider {
        pub(crate) fn new(reply: GetAttributesResponse) -> Self {
            Self {
                reply: Arc::new(Mutex::new(Ok(reply))),
                requests: Arc::new(Mutex::new(Vec::new())),
                delay_ms: Arc::new(AtomicU64::new(0)),
                peer_uid: None,
            }
        }

        pub(crate) fn reply(&self, reply: Result<GetAttributesResponse, Status>) {
            *self.reply.lock().expect("lock") = reply;
        }

        pub(crate) fn delay(&self, delay: Duration) {
            self.delay_ms.store(
                u64::try_from(delay.as_millis()).expect("delay fits"),
                Ordering::Relaxed,
            );
        }

        pub(crate) fn requests(&self) -> Vec<GetAttributesRequest> {
            self.requests.lock().expect("lock").clone()
        }
    }

    #[tonic::async_trait]
    impl PolicyInformationService for FakeProvider {
        async fn get_attributes(
            &self,
            request: Request<GetAttributesRequest>,
        ) -> Result<Response<GetAttributesResponse>, Status> {
            if let Some(uid) = self.peer_uid {
                authorize_peer(&request, uid)?;
            }
            self.requests
                .lock()
                .expect("lock")
                .push(request.into_inner());
            let delay = self.delay_ms.load(Ordering::Relaxed);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            self.reply.lock().expect("lock").clone().map(Response::new)
        }
    }

    pub(crate) fn current_uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    /// A `FOUND` reply carrying `value` as the context attributes.
    pub(crate) fn found(value: Value, ttl_seconds: u32) -> GetAttributesResponse {
        let Some(apf_proto::prost_types::value::Kind::StructValue(context)) =
            json_to_proto_value(&value).expect("struct").kind
        else {
            panic!("fixture must be an object");
        };
        GetAttributesResponse {
            context_attributes: Some(context),
            ttl_seconds,
            evidence_ref: "obs-1".to_owned(),
            status: AttributeStatus::Found as i32,
            age_seconds: 0,
        }
    }

    pub(crate) fn no_data() -> GetAttributesResponse {
        GetAttributesResponse {
            status: AttributeStatus::NoData as i32,
            ..GetAttributesResponse::default()
        }
    }

    /// A provider listening on a private Unix socket under `/tmp`.
    pub(crate) struct UnixServer {
        _dir: tempfile::TempDir,
        pub(crate) path: PathBuf,
        pub(crate) fake: FakeProvider,
        task: tokio::task::JoinHandle<()>,
    }

    impl UnixServer {
        pub(crate) fn start(mut fake: FakeProvider) -> Self {
            fake.peer_uid = Some(current_uid());
            let dir = tempfile::Builder::new()
                .prefix("apf-pip-")
                .tempdir_in("/tmp")
                .expect("tempdir");
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod dir");
            let path = dir.path().join("pip.sock");
            let listener = tokio::net::UnixListener::bind(&path).expect("bind");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod socket");
            let service = fake.clone();
            let task = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(PolicyInformationServiceServer::new(service))
                    .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                    .await
                    .expect("serve");
            });
            Self {
                _dir: dir,
                path,
                fake,
                task,
            }
        }
    }

    impl Drop for UnixServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A provider listening on a loopback TCP port without TLS.
    pub(crate) struct TcpServer {
        pub(crate) url: String,
        pub(crate) fake: FakeProvider,
        task: tokio::task::JoinHandle<()>,
    }

    impl TcpServer {
        pub(crate) async fn start(fake: FakeProvider) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let service = fake.clone();
            let task = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(PolicyInformationServiceServer::new(service))
                    .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                    .await
                    .expect("serve");
            });
            Self {
                url: format!("http://127.0.0.1:{port}"),
                fake,
                task,
            }
        }
    }

    impl Drop for TcpServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use apf_policy_eval::ProviderStatus;
    use apf_proto::pip_v1alpha1::EvaluationSubject;
    use serde_json::json;
    use tonic::{Code, Status};

    use super::testing::{FakeProvider, TcpServer, UnixServer, current_uid, found, no_data};
    use super::*;
    use crate::pip::provider::LookupResult;

    fn lookup(correlation_id: &str) -> Lookup {
        Lookup {
            subject: EvaluationSubject {
                user_subject: "user@corp.com".to_owned(),
                tool: "gitlab".to_owned(),
                action: "gitlab".to_owned(),
                user_subject_attestation: "caller".to_owned(),
                ..EvaluationSubject::default()
            },
            domain: "identity".to_owned(),
            correlation_id: correlation_id.to_owned(),
        }
    }

    fn budget() -> Duration {
        Duration::from_millis(500)
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("apf-pip-")
            .tempdir_in("/tmp")
            .expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        dir
    }

    fn bind_socket(dir: &Path, mode: u32) -> (std::os::unix::net::UnixListener, PathBuf) {
        let path = dir.join("pip.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        (listener, path)
    }

    #[test]
    fn check_endpoint_accepts_a_private_socket() {
        let dir = private_dir();
        let (_listener, path) = bind_socket(dir.path(), 0o600);
        check_endpoint(&path, current_uid()).expect("private socket passes");
        GrpcTransport::unix(path, current_uid(), 4).expect("constructor passes");
    }

    #[test]
    fn check_endpoint_allows_group_access_and_rejects_other_access() {
        let dir = private_dir();
        let (_listener, path) = bind_socket(dir.path(), 0o660);
        check_endpoint(&path, current_uid()).expect("group access passes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o662)).expect("chmod");
        let error = check_endpoint(&path, current_uid()).expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Misconfigured);
        assert!(error.to_string().contains("other users"), "{error}");
    }

    #[test]
    fn check_endpoint_rejects_a_socket_the_gateway_cannot_connect_to() {
        if current_uid() == 0 {
            // Root connects whatever the mode bits say.
            return;
        }
        let dir = private_dir();
        let (_listener, path) = bind_socket(dir.path(), 0o400);
        let error = check_endpoint(&path, current_uid()).expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Misconfigured);
        assert!(error.to_string().contains("not connectable"), "{error}");
        assert!(GrpcTransport::unix(path, current_uid(), 4).is_err());
    }

    #[test]
    fn check_endpoint_rejects_a_regular_file() {
        let dir = private_dir();
        let path = dir.path().join("pip.sock");
        std::fs::write(&path, b"").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let error = check_endpoint(&path, current_uid()).expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Misconfigured);
    }

    #[test]
    fn check_endpoint_rejects_a_foreign_owner_and_a_missing_socket() {
        let dir = private_dir();
        let (_listener, path) = bind_socket(dir.path(), 0o600);
        let error = check_endpoint(&path, current_uid() + 1).expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Unauthorized);
        assert!(GrpcTransport::unix(path, current_uid() + 1, 4).is_err());

        let missing = dir.path().join("absent.sock");
        let error = check_endpoint(&missing, current_uid()).expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Unavailable);
        assert!(GrpcTransport::unix(missing, current_uid(), 4).is_err());
    }

    #[test]
    fn check_endpoint_rejects_a_world_writable_ancestor() {
        let dir = private_dir();
        let (_listener, path) = bind_socket(dir.path(), 0o600);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        let error = check_endpoint(&path, current_uid()).expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Misconfigured);
        assert!(error.to_string().contains("writable"), "{error}");
    }

    #[test]
    fn ancestor_rule_covers_ownership_and_sticky_directories() {
        // The rules are pure functions of the uids they are given; fixed non-root
        // uids keep the cases distinct whoever runs the tests.
        let me: u32 = 1000;
        let peer = me + 1;
        assert!(
            ancestor_rule(true, 0, 0o40755, me, peer).is_ok(),
            "root dir"
        );
        assert!(
            ancestor_rule(true, me, 0o40700, me, peer).is_ok(),
            "own dir"
        );
        assert!(
            ancestor_rule(true, peer, 0o40750, me, peer).is_ok(),
            "peer dir"
        );
        assert!(
            ancestor_rule(true, 0, 0o41777, me, peer).is_ok(),
            "sticky /tmp"
        );
        let foreign = ancestor_rule(true, 4242, 0o40755, me, peer).expect_err("foreign");
        assert!(foreign.contains("uid 4242"), "{foreign}");
        assert!(
            ancestor_rule(true, 0, 0o40777, me, peer).is_err(),
            "root, not sticky"
        );
        assert!(
            ancestor_rule(true, me, 0o41777, me, peer).is_err(),
            "sticky but not root"
        );
        assert!(
            ancestor_rule(false, me, 0o100600, me, peer).is_err(),
            "not a directory"
        );

        assert!(socket_rule(true, me, 0o140600, me).is_ok());
        assert!(socket_rule(true, me, 0o140660, me).is_ok());
        assert!(socket_rule(false, me, 0o100600, me).is_err());
        assert_eq!(
            socket_rule(true, me, 0o140600, peer)
                .expect_err("owner")
                .status(),
            ProviderStatus::Unauthorized
        );
    }

    #[test]
    fn socket_rule_allows_group_access_and_rejects_other_access() {
        let me = current_uid();
        let peer = me + 1;
        assert!(
            socket_rule(true, peer, 0o140660, peer).is_ok(),
            "foreign owner granting group access"
        );
        assert!(
            socket_rule(true, me, 0o140600, me).is_ok(),
            "own owner-only socket"
        );
        let error = socket_rule(true, me, 0o140662, me).expect_err("other access");
        assert_eq!(error.status(), ProviderStatus::Misconfigured);
        assert!(error.to_string().contains("other users"), "{error}");
        assert!(
            socket_rule(true, peer, 0o140664, peer).is_err(),
            "other read"
        );
    }

    #[tokio::test]
    async fn peer_check_rejects_a_mismatched_uid() {
        let (left, _right) = UnixStream::pair().expect("pair");
        verify_peer(&left, current_uid()).expect("own uid passes");
        let error = verify_peer(&left, current_uid() + 1).expect_err("rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error
                .get_ref()
                .is_some_and(|inner| inner.is::<PeerUidMismatch>())
        );

        // The mismatch is found however deeply a transport wraps it.
        let chained = io::Error::new(io::ErrorKind::ConnectionRefused, error);
        assert_eq!(
            classify_error_chain(&chained).status(),
            ProviderStatus::Unauthorized
        );
        let plain = io::Error::new(io::ErrorKind::PermissionDenied, "eacces");
        assert_eq!(
            classify_error_chain(&plain).status(),
            ProviderStatus::Unavailable
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connecting_to_a_peer_with_the_wrong_uid_is_unauthorized() {
        let server = UnixServer::start(FakeProvider::new(found(
            json!({"identity": {"employee": true}}),
            30,
        )));
        let error = connect_unix(server.path.clone(), current_uid() + 1)
            .await
            .expect_err("rejected");
        assert_eq!(connect_error(&error).status(), ProviderStatus::Unauthorized);

        // The pre-connect check also refuses a socket owned by another UID.
        let transport = GrpcTransport {
            target: Target::Unix {
                socket: server.path.clone(),
                peer_uid: current_uid() + 1,
            },
            channel: Mutex::new(None),
            permits: Semaphore::new(4),
            max_in_flight: 4,
        };
        let error = transport
            .lookup(lookup("req-1"), budget())
            .await
            .expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Unauthorized);
        assert!(server.fake.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_over_a_unix_socket_returns_validated_attributes() {
        let server = UnixServer::start(FakeProvider::new(found(
            json!({"identity": {"employee": true, "groups": ["eng"]}}),
            30,
        )));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        let LookupResult::Found(attributes) = transport
            .lookup(lookup("req-1"), budget())
            .await
            .expect("found")
        else {
            panic!("expected attributes");
        };
        assert_eq!(attributes.claims["employee"], json!(true));
        assert_eq!(attributes.ttl_seconds, 30);
        assert_eq!(attributes.evidence_ref.as_deref(), Some("obs-1"));

        let requests = server.fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].domains, ["identity"]);
        assert_eq!(requests[0].correlation_id, "req-1");
        let subject = requests[0].subject.as_ref().expect("subject");
        assert_eq!(subject.user_subject, "user@corp.com");
        assert_eq!(subject.action, "gitlab");
        assert!(subject.args.is_none());

        server.fake.reply(Ok(no_data()));
        assert_eq!(
            transport.lookup(lookup("req-2"), budget()).await,
            Ok(LookupResult::NoData)
        );
        assert!(transport.channel.lock().await.is_some(), "channel reused");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_over_loopback_http_without_tls() {
        let server = TcpServer::start(FakeProvider::new(found(
            json!({"identity": {"employee": true}}),
            30,
        )))
        .await;
        let transport = GrpcTransport::https(&server.url, None, 4).expect("transport");
        let result = transport
            .lookup(lookup("req-1"), budget())
            .await
            .expect("found");
        assert!(matches!(result, LookupResult::Found(_)));
        assert_eq!(server.fake.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn grpc_status_codes_map_onto_the_taxonomy() {
        let server = UnixServer::start(FakeProvider::new(no_data()));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        let cases = [
            (Code::DeadlineExceeded, ProviderStatus::Timeout),
            (Code::Cancelled, ProviderStatus::Timeout),
            (Code::Unavailable, ProviderStatus::Unavailable),
            (Code::ResourceExhausted, ProviderStatus::Capacity),
            (Code::InvalidArgument, ProviderStatus::InvalidInput),
            (Code::Unauthenticated, ProviderStatus::Unauthorized),
            (Code::PermissionDenied, ProviderStatus::Unauthorized),
            (Code::Unimplemented, ProviderStatus::Misconfigured),
            (Code::FailedPrecondition, ProviderStatus::Misconfigured),
            (Code::Internal, ProviderStatus::Unavailable),
            (Code::NotFound, ProviderStatus::Unavailable),
            (Code::OutOfRange, ProviderStatus::InvalidOutput),
        ];
        for (code, expected) in cases {
            server
                .fake
                .reply(Err(Status::new(code, "provider says no")));
            let error = transport
                .lookup(lookup("req"), budget())
                .await
                .expect_err("status is an error");
            assert_eq!(error.status(), expected, "{code:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transport_failures_drop_the_channel_and_application_errors_keep_it() {
        let server = UnixServer::start(FakeProvider::new(no_data()));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        transport
            .lookup(lookup("req"), budget())
            .await
            .expect("no data");
        assert!(transport.channel.lock().await.is_some());

        server
            .fake
            .reply(Err(Status::invalid_argument("bad subject")));
        let error = transport
            .lookup(lookup("req"), budget())
            .await
            .expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::InvalidInput);
        assert!(transport.channel.lock().await.is_some(), "kept");

        server.fake.reply(Err(Status::unavailable("draining")));
        let error = transport
            .lookup(lookup("req"), budget())
            .await
            .expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::Unavailable);
        assert!(transport.channel.lock().await.is_none(), "dropped");

        server.fake.reply(Ok(no_data()));
        transport
            .lookup(lookup("req"), budget())
            .await
            .expect("reconnected");
        assert!(transport.channel.lock().await.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_provider_times_out_within_the_budget_and_drops_the_channel() {
        let server = UnixServer::start(FakeProvider::new(no_data()));
        server.fake.delay(Duration::from_millis(400));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        let started = std::time::Instant::now();
        let error = transport
            .lookup(lookup("req"), Duration::from_millis(50))
            .await
            .expect_err("timed out");
        assert_eq!(error.status(), ProviderStatus::Timeout);
        assert!(started.elapsed() < Duration::from_millis(350));
        assert!(transport.channel.lock().await.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_flight_limit_yields_capacity() {
        let server = UnixServer::start(FakeProvider::new(no_data()));
        server.fake.delay(Duration::from_millis(200));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 1).expect("transport");
        assert_eq!(transport.max_in_flight(), 1);
        let (first, second) = tokio::join!(
            transport.lookup(lookup("a"), budget()),
            transport.lookup(lookup("b"), budget())
        );
        assert_eq!(first, Ok(LookupResult::NoData));
        assert_eq!(second, Err(ProviderError::Capacity));
        transport
            .lookup(lookup("c"), budget())
            .await
            .expect("permit released");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_requests_are_rejected_before_sending() {
        let server = UnixServer::start(FakeProvider::new(no_data()));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        let error = transport
            .lookup(lookup(&"x".repeat(MAX_MESSAGE_BYTES + 1)), budget())
            .await
            .expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::InvalidInput);
        assert!(server.fake.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_responses_are_invalid_output() {
        let server = UnixServer::start(FakeProvider::new(found(
            json!({"identity": {"pad": "x".repeat(MAX_MESSAGE_BYTES + 1)}}),
            30,
        )));
        let transport =
            GrpcTransport::unix(server.path.clone(), current_uid(), 4).expect("transport");
        let error = transport
            .lookup(lookup("req"), budget())
            .await
            .expect_err("rejected");
        assert_eq!(error.status(), ProviderStatus::InvalidOutput);
        assert_eq!(server.fake.requests().len(), 1, "the provider answered");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unreachable_socket_is_unavailable() {
        let dir = private_dir();
        let (listener, path) = bind_socket(dir.path(), 0o600);
        let transport = GrpcTransport::unix(path.clone(), current_uid(), 4).expect("transport");
        drop(listener);
        let error = transport
            .lookup(lookup("req"), budget())
            .await
            .expect_err("nobody listens");
        assert_eq!(error.status(), ProviderStatus::Unavailable);
    }

    fn tls_files(dir: &Path, key_mode: u32) -> TlsConfig {
        let write = |name: &str, mode: u32| {
            let path = dir.join(name);
            std::fs::write(&path, b"not a pem\n").expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            path
        };
        TlsConfig {
            ca_file: write("ca.pem", 0o644),
            client_cert_file: write("client.pem", 0o644),
            client_key_file: write("client.key", key_mode),
        }
    }

    #[test]
    fn https_constructor_checks_the_url_and_tls_pairing() {
        assert!(GrpcTransport::https("https://pip.example.com:8443", None, 4).is_err());
        assert!(GrpcTransport::https("http://pip.example.com", None, 4).is_err());
        assert!(GrpcTransport::https("ftp://127.0.0.1", None, 4).is_err());
        assert!(GrpcTransport::https("not a url", None, 4).is_err());
        for loopback in ["http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9"] {
            let transport = GrpcTransport::https(loopback, None, 4).expect(loopback);
            assert_eq!(transport.max_in_flight(), 4);
        }
        assert!(GrpcTransport::https("http://127.0.0.1:9", None, 0).is_err());

        let dir = private_dir();
        let tls = tls_files(dir.path(), 0o600);
        assert!(GrpcTransport::https("http://127.0.0.1:9", Some(&tls), 4).is_err());
        // The files pass their checks; the fixture bytes are not certificates.
        let error = GrpcTransport::https("https://pip.example.com", Some(&tls), 4)
            .expect_err("fixture bytes are not PEM");
        assert!(error.to_string().contains("TLS material"), "{error}");
    }

    #[test]
    fn https_constructor_checks_tls_file_modes() {
        let dir = private_dir();
        let tls = tls_files(dir.path(), 0o640);
        let error = GrpcTransport::https("https://pip.example.com", Some(&tls), 4)
            .expect_err("group-readable key");
        assert!(error.to_string().contains("client_key_file"), "{error}");

        let tls = tls_files(dir.path(), 0o600);
        std::fs::set_permissions(&tls.ca_file, std::fs::Permissions::from_mode(0o666))
            .expect("chmod");
        let error = GrpcTransport::https("https://pip.example.com", Some(&tls), 4)
            .expect_err("world-writable ca");
        assert!(error.to_string().contains("ca_file"), "{error}");

        let missing = TlsConfig {
            ca_file: dir.path().join("absent.pem"),
            ..tls_files(dir.path(), 0o600)
        };
        assert!(GrpcTransport::https("https://pip.example.com", Some(&missing), 4).is_err());
    }

    #[test]
    fn checked_read_rejects_symlinks_special_files_and_oversized_files() {
        let dir = private_dir();
        let path = dir.path().join("material.pem");
        std::fs::write(&path, b"bytes").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(read_checked_file(&path, true, 64).expect("ok"), b"bytes");
        assert_eq!(read_checked_file(&path, false, 64).expect("ok"), b"bytes");
        assert!(read_checked_file(&path, true, 4).is_err(), "over the cap");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        assert!(read_checked_file(&path, true, 64).is_err(), "owner-only");
        assert!(read_checked_file(&path, false, 64).is_ok(), "shared");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).expect("chmod");
        assert!(read_checked_file(&path, false, 64).is_err(), "writable");

        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(read_checked_file(&link, false, 64).is_err(), "symlink");
        assert!(
            read_checked_file(dir.path(), false, 64).is_err(),
            "directory"
        );
        assert!(read_checked_file(&dir.path().join("absent"), false, 64).is_err());
    }
}
