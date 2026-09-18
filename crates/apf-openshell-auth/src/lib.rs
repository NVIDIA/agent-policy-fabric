// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication and authorization for calls from an OpenShell gateway or
//! sandbox supervisor into an APF-hosted OpenShell extension (the gateway
//! interceptor or supervisor middleware surfaces).
//!
//! OpenShell uses one Ed25519 signing authority for both sandbox bootstrap and
//! extension credentials. This verifier therefore requires the extension JWT
//! type, exact audience, and exact caller shape in addition to a valid signature.

pub mod audit;

use apf_audit::ComponentAudit;

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
#[cfg(unix)]
use nix::fcntl::OFlag;
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::{Request, Status};

const AUTHORIZATION_METADATA: &str = "authorization";
const BEARER_PREFIX: &str = "Bearer ";
const EXTENSION_JWT_TYPE: &str = "openshell-ext+jwt";
const ISSUER_PREFIX: &str = "openshell-gateway:";
const SUPERVISOR_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";
const MAX_TRUST_PROFILE_BYTES: usize = 64 * 1024;
const MAX_PROTOCOL_LIFETIME_SECS: u64 = 3_600;
const MAX_CLOCK_LEEWAY_SECS: u64 = 300;

/// Configuration failures that prevent extension authentication from starting.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExtensionAuthConfigError {
    /// The trust profile could not be opened or read.
    #[error("failed to read extension authentication trust profile")]
    Read(#[source] std::io::Error),
    /// The configured path does not resolve to a regular file.
    #[error("extension authentication trust profile is not a regular file")]
    NotAFile,
    /// The trust profile can be modified by another local user.
    #[error("extension authentication trust profile must not be group or world writable")]
    UnsafePermissions,
    /// The path resolved to a different file while it was being opened.
    #[error("extension authentication trust profile changed while being opened")]
    ChangedWhileOpening,
    /// The trust profile exceeds the fixed startup input limit.
    #[error("extension authentication trust profile exceeds {MAX_TRUST_PROFILE_BYTES} bytes")]
    TooLarge,
    /// TOML syntax or field types are invalid.
    #[error("extension authentication trust profile is not valid TOML")]
    InvalidToml,
    /// The issuer does not identify one exact OpenShell gateway.
    #[error("extension authentication issuer must be openshell-gateway:<gateway_id>")]
    InvalidIssuer,
    /// The audience is blank.
    #[error("extension authentication audience must not be blank")]
    InvalidAudience,
    /// The signing key identifier is blank.
    #[error("extension authentication kid must not be blank")]
    InvalidKeyId,
    /// The accepted token lifetime is zero or exceeds the protocol ceiling.
    #[error("extension authentication max_lifetime_secs must be between 1 and 3600")]
    InvalidLifetime,
    /// The clock leeway exceeds the bounded allowance.
    #[error("extension authentication leeway_secs must not exceed 300")]
    InvalidLeeway,
    /// The configured key is not an Ed25519 public key in PEM form.
    #[error("extension authentication public_key_pem is not a valid Ed25519 public key")]
    InvalidPublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustProfile {
    issuer: String,
    audience: String,
    kid: String,
    public_key_pem: String,
    max_lifetime_secs: u64,
    leeway_secs: u64,
}

/// The OpenShell component authenticated by an extension JWT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionCallerKind {
    /// An OpenShell gateway control-plane call.
    Gateway,
    /// A sandbox supervisor data-plane call.
    Supervisor,
}

/// Validated caller identity inserted into a tonic request before dispatch.
#[derive(Clone)]
pub struct AuthenticatedCaller {
    kind: ExtensionCallerKind,
    sandbox_id: Option<String>,
}

impl AuthenticatedCaller {
    /// Returns which OpenShell component made the call.
    #[must_use]
    pub const fn kind(&self) -> ExtensionCallerKind {
        self.kind
    }

    /// Returns the authenticated sandbox identifier for supervisor callers.
    #[must_use]
    pub fn sandbox_id(&self) -> Option<&str> {
        self.sandbox_id.as_deref()
    }

    /// Builds a caller identity for adapter-crate authorization tests.
    #[doc(hidden)]
    pub fn for_test(kind: ExtensionCallerKind, sandbox_id: Option<&str>) -> Self {
        Self {
            kind,
            sandbox_id: sandbox_id.map(str::to_owned),
        }
    }
}

/// Whether a server surface requires an authenticated OpenShell extension
/// caller before dispatching a request, or has caller authentication
/// deliberately disabled (local research / dev opt-out).
#[derive(Clone)]
pub enum AuthenticationMode {
    /// Every request must carry a caller identity authenticated by
    /// [`ExtensionAuthVerifier`] before this RPC's `authorize` check runs.
    Required { expected_audience: String },
    /// Caller authentication is disabled for this listener.
    Insecure,
}

/// Why an authorization check on an already-authenticated request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationFailure {
    /// No [`AuthenticatedCaller`] extension was found on the request, even
    /// though the server is in [`AuthenticationMode::Required`]. This fails
    /// closed if a runtime wraps the service without the verifier interceptor.
    MissingCaller,
    /// A caller was authenticated, but its [`ExtensionCallerKind`] is not in
    /// the RPC's allowed list.
    CallerNotAllowed,
}

impl AuthorizationFailure {
    #[must_use]
    pub fn into_status(self) -> Status {
        match self {
            Self::MissingCaller => {
                Status::unauthenticated("OpenShell extension caller is not authenticated")
            }
            Self::CallerNotAllowed => Status::permission_denied(
                "OpenShell extension caller is not authorized for this RPC",
            ),
        }
    }
}

impl AuthenticationMode {
    /// Checks that an already-authenticated request's caller kind is one of
    /// `allowed`. Returns `Ok(None)` without checking anything when this mode
    /// is [`AuthenticationMode::Insecure`].
    pub fn authorize<'a, T>(
        &self,
        request: &'a Request<T>,
        allowed: &[ExtensionCallerKind],
    ) -> Result<Option<&'a AuthenticatedCaller>, AuthorizationFailure> {
        let Self::Required { .. } = self else {
            return Ok(None);
        };
        // The authenticated server inserts this extension before dispatch.
        // Its absence fails closed if another runtime wraps the service
        // incorrectly.
        let caller = request
            .extensions()
            .get::<AuthenticatedCaller>()
            .ok_or(AuthorizationFailure::MissingCaller)?;
        if !allowed.contains(&caller.kind()) {
            return Err(AuthorizationFailure::CallerNotAllowed);
        }
        Ok(Some(caller))
    }

    /// The configured audience this mode advertises, or an empty string in
    /// [`AuthenticationMode::Insecure`] mode.
    #[must_use]
    pub fn expected_audience(&self) -> &str {
        match self {
            Self::Required { expected_audience } => expected_audience,
            Self::Insecure => "",
        }
    }
}

/// A tonic server wrapped with [`ExtensionAuthVerifier`] as its request
/// interceptor. Each adapter crate builds its own size-limited `S` before
/// wrapping it here.
pub type Authenticated<S> = InterceptedService<S, ExtensionAuthVerifier>;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireCallerKind {
    Gateway,
    Supervisor,
}

#[derive(Deserialize)]
struct ExtensionJwtClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    caller_kind: WireCallerKind,
    #[serde(default)]
    sandbox_id: SandboxIdClaim,
}

#[derive(Default)]
enum SandboxIdClaim {
    #[default]
    Absent,
    Present(String),
}

impl<'de> Deserialize<'de> for SandboxIdClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserializing directly as String preserves the distinction between
        // an omitted field and an explicitly signed null. Null and every
        // non-string JSON type fail the entire JWT claim decode.
        String::deserialize(deserializer).map(Self::Present)
    }
}

struct VerifierState {
    issuer: String,
    audience: String,
    kid: String,
    decoding_key: DecodingKey,
    validation: Validation,
    max_lifetime_secs: i64,
    leeway_secs: i64,
}

enum AuthFailure {
    InvalidCredential,
    InvalidSystemTime,
}

/// Strict verifier and tonic interceptor for OpenShell extension credentials.
///
/// The verifier owns only public trust material. It never records token IDs and
/// deliberately accepts a reused token until its bounded expiry.
#[derive(Clone)]
pub struct ExtensionAuthVerifier {
    state: Arc<VerifierState>,
    /// The surface's emitter. Supplied rather than built here: a refused
    /// credential is recorded under the listener that refused it, and this
    /// type has no listener of its own.
    audit: ComponentAudit,
}

impl fmt::Debug for ExtensionAuthVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionAuthVerifier")
            .finish_non_exhaustive()
    }
}

impl ExtensionAuthVerifier {
    /// Attach the emitting surface's audit sink.
    ///
    /// Without it a rejected credential is refused but unrecorded, so this is
    /// the difference between seeing credential probing and not.
    #[must_use]
    pub fn with_audit(mut self, audit: ComponentAudit) -> Self {
        self.audit = audit;
        self
    }

    /// Loads and validates one bounded TOML trust profile.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionAuthConfigError`] when the file cannot be read within
    /// the input limit or any trust field violates the extension protocol.
    pub async fn from_trust_file(path: &Path) -> Result<Self, ExtensionAuthConfigError> {
        let file = open_trust_file(path).await?;

        // The checked open returns only the same regular file inspected before
        // opening. The capped view independently bounds a file that grows.
        let mut bytes = Vec::with_capacity(MAX_TRUST_PROFILE_BYTES + 1);
        file.take((MAX_TRUST_PROFILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(ExtensionAuthConfigError::Read)?;
        if bytes.len() > MAX_TRUST_PROFILE_BYTES {
            return Err(ExtensionAuthConfigError::TooLarge);
        }

        Self::from_toml(&bytes)
    }

    /// Returns the exact audience advertised by the authenticated server.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.state.audience
    }

    fn from_toml(bytes: &[u8]) -> Result<Self, ExtensionAuthConfigError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ExtensionAuthConfigError::InvalidToml)?;
        let profile: TrustProfile =
            toml::from_str(text).map_err(|_| ExtensionAuthConfigError::InvalidToml)?;

        if !valid_gateway_issuer(&profile.issuer) {
            return Err(ExtensionAuthConfigError::InvalidIssuer);
        }
        if !valid_exact_text(&profile.audience) {
            return Err(ExtensionAuthConfigError::InvalidAudience);
        }
        if !valid_exact_text(&profile.kid) {
            return Err(ExtensionAuthConfigError::InvalidKeyId);
        }
        if !(1..=MAX_PROTOCOL_LIFETIME_SECS).contains(&profile.max_lifetime_secs) {
            return Err(ExtensionAuthConfigError::InvalidLifetime);
        }
        if profile.leeway_secs > MAX_CLOCK_LEEWAY_SECS {
            return Err(ExtensionAuthConfigError::InvalidLeeway);
        }

        let decoding_key = DecodingKey::from_ed_pem(profile.public_key_pem.as_bytes())
            .map_err(|_| ExtensionAuthConfigError::InvalidPublicKey)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.set_issuer(&[&profile.issuer]);
        validation.set_audience(&[&profile.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp"]);
        // `nbf` remains optional in the extension contract, but a signer that
        // includes it must not be able to make a token valid prematurely.
        validation.validate_nbf = true;
        validation.leeway = profile.leeway_secs;

        Ok(Self {
            state: Arc::new(VerifierState {
                issuer: profile.issuer,
                audience: profile.audience,
                kid: profile.kid,
                decoding_key,
                validation,
                max_lifetime_secs: profile.max_lifetime_secs as i64,
                leeway_secs: profile.leeway_secs as i64,
            }),
            // Disabled until a surface attaches its own; see `with_audit`.
            audit: ComponentAudit::disabled(),
        })
    }

    fn authenticate(&self, metadata: &MetadataMap) -> Result<AuthenticatedCaller, AuthFailure> {
        let token = singular_bearer_token(metadata).ok_or(AuthFailure::InvalidCredential)?;
        self.verify_token(token)
    }

    fn verify_token(&self, token: &str) -> Result<AuthenticatedCaller, AuthFailure> {
        let header = decode_header(token).map_err(|_| AuthFailure::InvalidCredential)?;
        if header.alg != Algorithm::EdDSA
            || header.typ.as_deref() != Some(EXTENSION_JWT_TYPE)
            || header.kid.as_deref() != Some(self.state.kid.as_str())
        {
            return Err(AuthFailure::InvalidCredential);
        }

        let claims =
            decode::<ExtensionJwtClaims>(token, &self.state.decoding_key, &self.state.validation)
                .map_err(|_| AuthFailure::InvalidCredential)?
                .claims;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthFailure::InvalidSystemTime)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| AuthFailure::InvalidSystemTime)?;
        if claims.iss != self.state.issuer
            || claims.aud != self.state.audience
            || claims.sub.trim().is_empty()
            || claims.jti.trim().is_empty()
            || claims.iat <= 0
            || claims.exp <= 0
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > self.state.max_lifetime_secs
            || claims.iat > now.saturating_add(self.state.leeway_secs)
        {
            return Err(AuthFailure::InvalidCredential);
        }

        match claims.caller_kind {
            WireCallerKind::Gateway
                if claims.sub == claims.iss
                    && matches!(&claims.sandbox_id, SandboxIdClaim::Absent) =>
            {
                Ok(AuthenticatedCaller {
                    kind: ExtensionCallerKind::Gateway,
                    sandbox_id: None,
                })
            }
            WireCallerKind::Supervisor => {
                let SandboxIdClaim::Present(sandbox_id) = claims.sandbox_id else {
                    return Err(AuthFailure::InvalidCredential);
                };
                if sandbox_id.trim().is_empty() || sandbox_id.trim() != sandbox_id {
                    return Err(AuthFailure::InvalidCredential);
                }
                if claims.sub != format!("{SUPERVISOR_SUBJECT_PREFIX}{sandbox_id}") {
                    return Err(AuthFailure::InvalidCredential);
                }
                Ok(AuthenticatedCaller {
                    kind: ExtensionCallerKind::Supervisor,
                    sandbox_id: Some(sandbox_id),
                })
            }
            WireCallerKind::Gateway => Err(AuthFailure::InvalidCredential),
        }
    }
}

#[cfg(unix)]
async fn open_trust_file(path: &Path) -> Result<tokio::fs::File, ExtensionAuthConfigError> {
    use std::os::unix::fs::MetadataExt as _;

    let inspected = tokio::fs::symlink_metadata(path)
        .await
        .map_err(ExtensionAuthConfigError::Read)?;
    validate_trust_metadata(&inspected)?;

    // O_NOFOLLOW closes the symlink race and O_NONBLOCK prevents a file-type
    // swap to a FIFO from blocking startup before the opened handle is checked.
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits());
    let file = options
        .open(path)
        .await
        .map_err(ExtensionAuthConfigError::Read)?;
    let opened = file
        .metadata()
        .await
        .map_err(ExtensionAuthConfigError::Read)?;
    validate_trust_metadata(&opened)?;
    if inspected.dev() != opened.dev() || inspected.ino() != opened.ino() {
        return Err(ExtensionAuthConfigError::ChangedWhileOpening);
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_trust_metadata(metadata: &std::fs::Metadata) -> Result<(), ExtensionAuthConfigError> {
    use std::os::unix::fs::MetadataExt as _;

    // symlink_metadata reports a symlink itself as non-regular, so this rejects
    // links, FIFOs, devices, sockets, and directories before open.
    if !metadata.is_file() {
        return Err(ExtensionAuthConfigError::NotAFile);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ExtensionAuthConfigError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
async fn open_trust_file(path: &Path) -> Result<tokio::fs::File, ExtensionAuthConfigError> {
    let inspected = tokio::fs::symlink_metadata(path)
        .await
        .map_err(ExtensionAuthConfigError::Read)?;
    if inspected.file_type().is_symlink() || !inspected.is_file() {
        return Err(ExtensionAuthConfigError::NotAFile);
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(ExtensionAuthConfigError::Read)?;
    if !file
        .metadata()
        .await
        .map_err(ExtensionAuthConfigError::Read)?
        .is_file()
    {
        return Err(ExtensionAuthConfigError::NotAFile);
    }
    Ok(file)
}

fn valid_exact_text(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}

fn valid_gateway_issuer(issuer: &str) -> bool {
    let Some(gateway_id) = issuer.strip_prefix(ISSUER_PREFIX) else {
        return false;
    };
    // OpenShell treats the gateway ID suffix as opaque. Only blank, padded, or
    // control-bearing values are malformed; separators remain part of the ID.
    valid_exact_text(gateway_id)
}

impl Interceptor for ExtensionAuthVerifier {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let caller = self.authenticate(request.metadata()).map_err(|_| {
            // Recorded here because the request never reaches a service
            // method: without this, credential probing leaves no trace.
            if let Err(e) = audit::emit_credential_invalid(&self.audit) {
                tracing::warn!(error = %e, "audit emission failed for rejected credential");
            }
            // All credential failures share one response and no token-derived
            // data reaches logs or status text.
            Status::unauthenticated("invalid OpenShell extension bearer credential")
        })?;
        // Downstream handlers receive only the bounded caller identity. The
        // raw bearer credential has no purpose after signature validation and
        // must not survive into middleware dispatch or diagnostic layers.
        request.metadata_mut().remove(AUTHORIZATION_METADATA);
        request.extensions_mut().insert(caller);
        Ok(request)
    }
}

fn singular_bearer_token(metadata: &MetadataMap) -> Option<&str> {
    let mut values = metadata.get_all(AUTHORIZATION_METADATA).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let token = value.strip_prefix(BEARER_PREFIX)?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

#[cfg(test)]
pub(crate) mod tests {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};
    use tonic::Code;

    use super::*;

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2+Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8=\n-----END PUBLIC KEY-----\n";
    const ISSUER: &str = "openshell-gateway:test-gateway";
    const AUDIENCE: &str = "urn:openshell:extension:middleware:apf";
    const KID: &str = "test-kid";

    fn profile(max_lifetime_secs: u64, leeway_secs: u64) -> Vec<u8> {
        format!(
            r#"issuer = "{ISSUER}"
audience = "{AUDIENCE}"
kid = "{KID}"
public_key_pem = '''{TEST_PUBLIC_KEY}'''
max_lifetime_secs = {max_lifetime_secs}
leeway_secs = {leeway_secs}
"#,
        )
        .into_bytes()
    }

    pub(crate) fn verifier(max_lifetime_secs: u64, leeway_secs: u64) -> ExtensionAuthVerifier {
        ExtensionAuthVerifier::from_toml(&profile(max_lifetime_secs, leeway_secs))
            .expect("test trust profile must be valid")
    }

    pub(crate) fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must follow the Unix epoch")
            .as_secs() as i64
    }

    pub(crate) fn gateway_claims(now: i64) -> Value {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": ISSUER,
            "iat": now,
            "exp": now + 300,
            "jti": "gateway-token",
            "caller_kind": "gateway"
        })
    }

    fn supervisor_claims(now: i64, sandbox_id: &str) -> Value {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": format!("{SUPERVISOR_SUBJECT_PREFIX}{sandbox_id}"),
            "iat": now,
            "exp": now + 300,
            "jti": "supervisor-token",
            "caller_kind": "supervisor",
            "sandbox_id": sandbox_id
        })
    }

    fn extension_header() -> Header {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(EXTENSION_JWT_TYPE.to_string());
        header.kid = Some(KID.to_string());
        header
    }

    fn sign_with_header(claims: &Value, header: &Header) -> String {
        let key = EncodingKey::from_ed_pem(TEST_PRIVATE_KEY.as_bytes())
            .expect("test signing key must be valid");
        encode(header, claims, &key).expect("test token must encode")
    }

    pub(crate) fn sign(claims: &Value) -> String {
        sign_with_header(claims, &extension_header())
    }

    pub(crate) fn request_with_authorization(value: &str) -> Request<()> {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTHORIZATION_METADATA,
            value.parse().expect("test metadata must be ASCII"),
        );
        request
    }

    fn call(
        verifier: &ExtensionAuthVerifier,
        request: Request<()>,
    ) -> Result<Request<()>, Box<Status>> {
        verifier.clone().call(request).map_err(Box::new)
    }

    fn assert_rejected(verifier: &ExtensionAuthVerifier, token: &str) {
        let request = request_with_authorization(&format!("Bearer {token}"));
        assert_eq!(
            call(verifier, request)
                .expect_err("credential must be rejected")
                .code(),
            Code::Unauthenticated
        );
    }

    #[test]
    fn valid_gateway_and_supervisor_tokens_produce_bounded_caller_identity() {
        let verifier = verifier(300, 0);
        let now = now_secs();

        let gateway = call(
            &verifier,
            request_with_authorization(&format!("Bearer {}", sign(&gateway_claims(now)))),
        )
        .expect("gateway credential must authenticate");
        assert!(
            gateway.metadata().get(AUTHORIZATION_METADATA).is_none(),
            "verified bearer credentials must not reach dispatch"
        );
        let gateway = gateway
            .extensions()
            .get::<AuthenticatedCaller>()
            .expect("gateway caller must be attached");
        assert_eq!(gateway.kind(), ExtensionCallerKind::Gateway);
        assert_eq!(gateway.sandbox_id(), None);

        let supervisor = call(
            &verifier,
            request_with_authorization(&format!(
                "Bearer {}",
                sign(&supervisor_claims(now, "sandbox-a"))
            )),
        )
        .expect("supervisor credential must authenticate");
        let supervisor = supervisor
            .extensions()
            .get::<AuthenticatedCaller>()
            .expect("supervisor caller must be attached");
        assert_eq!(supervisor.kind(), ExtensionCallerKind::Supervisor);
        assert_eq!(supervisor.sandbox_id(), Some("sandbox-a"));
    }

    #[test]
    fn one_token_can_be_reused_within_its_bounded_lifetime() {
        let verifier = verifier(300, 0);
        let token = sign(&gateway_claims(now_secs()));

        for _ in 0..2 {
            let request = request_with_authorization(&format!("Bearer {token}"));
            call(&verifier, request)
                .expect("extension tokens are reusable until their bounded expiry");
        }
    }

    #[test]
    fn missing_duplicate_and_malformed_bearer_metadata_fail_closed() {
        let verifier = verifier(300, 0);
        assert_eq!(
            call(&verifier, Request::new(()))
                .expect_err("missing credential must fail")
                .code(),
            Code::Unauthenticated
        );

        let token = sign(&gateway_claims(now_secs()));
        let mut duplicate = request_with_authorization(&format!("Bearer {token}"));
        duplicate.metadata_mut().append(
            AUTHORIZATION_METADATA,
            format!("Bearer {token}")
                .parse()
                .expect("test metadata must be ASCII"),
        );
        assert_eq!(
            call(&verifier, duplicate)
                .expect_err("duplicate credential must fail")
                .code(),
            Code::Unauthenticated
        );

        for malformed in [
            "bearer token",
            "Bearer",
            "Bearer ",
            "Bearer  token",
            "Bearer token with-space",
            "Basic token",
        ] {
            let request = request_with_authorization(malformed);
            assert_eq!(
                call(&verifier, request)
                    .expect_err("malformed credential must fail")
                    .code(),
                Code::Unauthenticated,
                "accepted malformed metadata: {malformed:?}"
            );
        }
    }

    #[test]
    fn header_algorithm_type_and_key_id_are_exact() {
        let verifier = verifier(300, 0);
        let claims = gateway_claims(now_secs());

        let mut wrong_type = extension_header();
        wrong_type.typ = Some("JWT".to_string());
        assert_rejected(&verifier, &sign_with_header(&claims, &wrong_type));

        let mut missing_type = extension_header();
        missing_type.typ = None;
        assert_rejected(&verifier, &sign_with_header(&claims, &missing_type));

        let mut wrong_kid = extension_header();
        wrong_kid.kid = Some("another-kid".to_string());
        assert_rejected(&verifier, &sign_with_header(&claims, &wrong_kid));

        let mut missing_kid = extension_header();
        missing_kid.kid = None;
        assert_rejected(&verifier, &sign_with_header(&claims, &missing_kid));

        let mut wrong_algorithm = Header::new(Algorithm::HS256);
        wrong_algorithm.typ = Some(EXTENSION_JWT_TYPE.to_string());
        wrong_algorithm.kid = Some(KID.to_string());
        let token = encode(
            &wrong_algorithm,
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("test HMAC token must encode");
        assert_rejected(&verifier, &token);
    }

    #[test]
    fn issuer_and_scalar_audience_are_exact() {
        let verifier = verifier(300, 0);
        let now = now_secs();

        let mut wrong_issuer = gateway_claims(now);
        wrong_issuer["iss"] = json!("openshell-gateway:other");
        wrong_issuer["sub"] = json!("openshell-gateway:other");
        assert_rejected(&verifier, &sign(&wrong_issuer));

        let mut wrong_audience = gateway_claims(now);
        wrong_audience["aud"] = json!("urn:other");
        assert_rejected(&verifier, &sign(&wrong_audience));

        let mut array_audience = gateway_claims(now);
        array_audience["aud"] = json!([AUDIENCE]);
        assert_rejected(&verifier, &sign(&array_audience));
    }

    #[test]
    fn timestamps_must_be_positive_current_ordered_and_bounded() {
        let verifier = verifier(300, 0);
        let now = now_secs();

        let mut expired = gateway_claims(now - 600);
        expired["exp"] = json!(now - 60);
        assert_rejected(&verifier, &sign(&expired));

        let mut overlong = gateway_claims(now);
        overlong["exp"] = json!(now + 301);
        assert_rejected(&verifier, &sign(&overlong));

        let mut future = gateway_claims(now + 60);
        future["exp"] = json!(now + 120);
        assert_rejected(&verifier, &sign(&future));

        let mut future_not_before = gateway_claims(now);
        future_not_before["nbf"] = json!(now + 60);
        assert_rejected(&verifier, &sign(&future_not_before));

        let mut active_not_before = gateway_claims(now);
        active_not_before["nbf"] = json!(now - 60);
        let request = request_with_authorization(&format!("Bearer {}", sign(&active_not_before)));
        call(&verifier, request).expect("an optional active nbf claim must authenticate");

        for (iat, exp) in [(0, now + 1), (now, 0), (now, now), (now, now - 1)] {
            let mut invalid = gateway_claims(now);
            invalid["iat"] = json!(iat);
            invalid["exp"] = json!(exp);
            assert_rejected(&verifier, &sign(&invalid));
        }
    }

    #[test]
    fn configured_leeway_bounds_future_iat_without_extending_encoded_lifetime() {
        let verifier = verifier(300, 30);
        let now = now_secs();
        let accepted = gateway_claims(now + 15);
        let request = request_with_authorization(&format!("Bearer {}", sign(&accepted)));
        call(&verifier, request).expect("iat within configured leeway must authenticate");

        let mut rejected = gateway_claims(now + 90);
        rejected["exp"] = json!(now + 180);
        assert_rejected(&verifier, &sign(&rejected));
    }

    #[test]
    fn caller_shape_subject_and_required_text_claims_are_coherent() {
        let verifier = verifier(300, 0);
        let now = now_secs();

        let mut gateway_with_sandbox = gateway_claims(now);
        gateway_with_sandbox["sandbox_id"] = json!("sandbox-a");
        assert_rejected(&verifier, &sign(&gateway_with_sandbox));

        for malformed_sandbox_id in [
            json!(17),
            json!(true),
            json!(["sandbox-a"]),
            json!({"id": "sandbox-a"}),
        ] {
            let mut gateway = gateway_claims(now);
            gateway["sandbox_id"] = malformed_sandbox_id;
            assert_rejected(&verifier, &sign(&gateway));
        }

        let mut gateway_subject = gateway_claims(now);
        gateway_subject["sub"] = json!("spiffe://openshell/sandbox/sandbox-a");
        assert_rejected(&verifier, &sign(&gateway_subject));

        let mut supervisor_without_sandbox = supervisor_claims(now, "sandbox-a");
        supervisor_without_sandbox
            .as_object_mut()
            .expect("test claims must be an object")
            .remove("sandbox_id");
        assert_rejected(&verifier, &sign(&supervisor_without_sandbox));

        let mut supervisor_subject = supervisor_claims(now, "sandbox-a");
        supervisor_subject["sub"] = json!("spiffe://openshell/sandbox/sandbox-b");
        assert_rejected(&verifier, &sign(&supervisor_subject));

        for field in ["sub", "jti"] {
            let mut blank = gateway_claims(now);
            blank[field] = json!("   ");
            assert_rejected(&verifier, &sign(&blank));
        }
    }

    #[test]
    fn gateway_explicit_null_sandbox_id_is_rejected() {
        let verifier = verifier(300, 0);
        let mut claims = gateway_claims(now_secs());
        claims["sandbox_id"] = Value::Null;

        assert_rejected(&verifier, &sign(&claims));
    }

    #[test]
    fn trust_profile_is_closed_and_enforces_protocol_bounds() {
        let mut unknown = String::from_utf8(profile(300, 0)).expect("profile must be UTF-8");
        unknown.push_str("unexpected = true\n");
        assert!(matches!(
            ExtensionAuthVerifier::from_toml(unknown.as_bytes()),
            Err(ExtensionAuthConfigError::InvalidToml)
        ));

        for lifetime in [0, MAX_PROTOCOL_LIFETIME_SECS + 1] {
            assert!(matches!(
                ExtensionAuthVerifier::from_toml(&profile(lifetime, 0)),
                Err(ExtensionAuthConfigError::InvalidLifetime)
            ));
        }
        assert!(matches!(
            ExtensionAuthVerifier::from_toml(&profile(300, MAX_CLOCK_LEEWAY_SECS + 1)),
            Err(ExtensionAuthConfigError::InvalidLeeway)
        ));

        for issuer in [
            "https://gateway.example",
            "openshell-gateway:",
            "openshell-gateway: padded",
            "openshell-gateway:padded ",
            "openshell-gateway:line\\nbreak",
        ] {
            let invalid = String::from_utf8(profile(300, 0))
                .expect("profile must be UTF-8")
                .replace(ISSUER, issuer);
            assert!(matches!(
                ExtensionAuthVerifier::from_toml(invalid.as_bytes()),
                Err(ExtensionAuthConfigError::InvalidIssuer)
            ));
        }

        for issuer in [
            "openshell-gateway:edge/team-a",
            "openshell-gateway:edge:team-a",
        ] {
            let valid = String::from_utf8(profile(300, 0))
                .expect("profile must be UTF-8")
                .replace(ISSUER, issuer);
            ExtensionAuthVerifier::from_toml(valid.as_bytes())
                .expect("an opaque nonblank gateway ID suffix must be accepted");
        }

        for (field, value, expected) in [
            ("audience", " padded", "audience"),
            ("audience", "line\\nbreak", "audience"),
            ("kid", "padded ", "kid"),
            ("kid", "line\\tbreak", "kid"),
        ] {
            let valid = String::from_utf8(profile(300, 0)).expect("profile must be UTF-8");
            let original = if field == "audience" { AUDIENCE } else { KID };
            let invalid = valid.replace(
                &format!("{field} = \"{original}\""),
                &format!("{field} = \"{value}\""),
            );
            let error = ExtensionAuthVerifier::from_toml(invalid.as_bytes())
                .expect_err("padded or control-bearing trust text must fail");
            match expected {
                "audience" => {
                    assert!(matches!(error, ExtensionAuthConfigError::InvalidAudience))
                }
                "kid" => assert!(matches!(error, ExtensionAuthConfigError::InvalidKeyId)),
                _ => unreachable!("test fixture names one of two trust fields"),
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn trust_file_requires_a_stable_secure_regular_inode() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::time::Duration;

        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let directory = tempfile::tempdir().expect("temporary directory must be created");
        let trust = directory.path().join("trust.toml");
        std::fs::write(&trust, profile(300, 0)).expect("trust fixture must be written");
        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o644))
            .expect("trust fixture permissions must be set");
        ExtensionAuthVerifier::from_trust_file(&trust)
            .await
            .expect("secure regular trust files must load");

        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o664))
            .expect("trust fixture permissions must be changed");
        assert!(matches!(
            ExtensionAuthVerifier::from_trust_file(&trust).await,
            Err(ExtensionAuthConfigError::UnsafePermissions)
        ));
        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o644))
            .expect("trust fixture permissions must be restored");

        let link = directory.path().join("trust-link.toml");
        symlink(&trust, &link).expect("trust symlink fixture must be created");
        assert!(matches!(
            ExtensionAuthVerifier::from_trust_file(&link).await,
            Err(ExtensionAuthConfigError::NotAFile)
        ));

        let fifo = directory.path().join("trust.pipe");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("trust FIFO fixture must be created");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            ExtensionAuthVerifier::from_trust_file(&fifo),
        )
        .await
        .expect("FIFO rejection must not block startup");
        assert!(matches!(result, Err(ExtensionAuthConfigError::NotAFile)));
    }

    #[test]
    fn insecure_mode_authorizes_without_a_caller() {
        let mode = AuthenticationMode::Insecure;
        let request = Request::new(());
        assert!(
            mode.authorize(&request, &[ExtensionCallerKind::Gateway])
                .unwrap()
                .is_none()
        );
        assert_eq!(mode.expected_audience(), "");
    }

    #[test]
    fn required_mode_enforces_the_allowed_caller_list() {
        let mode = AuthenticationMode::Required {
            expected_audience: AUDIENCE.to_string(),
        };
        assert_eq!(mode.expected_audience(), AUDIENCE);

        let missing = Request::new(());
        assert!(matches!(
            mode.authorize(&missing, &[ExtensionCallerKind::Gateway]),
            Err(AuthorizationFailure::MissingCaller)
        ));

        let mut disallowed = Request::new(());
        disallowed
            .extensions_mut()
            .insert(AuthenticatedCaller::for_test(
                ExtensionCallerKind::Supervisor,
                Some("sandbox-a"),
            ));
        assert!(matches!(
            mode.authorize(&disallowed, &[ExtensionCallerKind::Gateway]),
            Err(AuthorizationFailure::CallerNotAllowed)
        ));

        let mut allowed = Request::new(());
        allowed
            .extensions_mut()
            .insert(AuthenticatedCaller::for_test(
                ExtensionCallerKind::Gateway,
                None,
            ));
        let caller = mode
            .authorize(&allowed, &[ExtensionCallerKind::Gateway])
            .expect("allowed caller kind must authorize")
            .expect("Required mode returns the authenticated caller");
        assert_eq!(caller.kind(), ExtensionCallerKind::Gateway);
    }
}

#[cfg(test)]
mod audit_tests {
    use super::tests::{gateway_claims, now_secs, request_with_authorization, sign, verifier};
    use super::*;
    use apf_audit::{AuditEvent, AuditIdentity, ComponentAudit};
    use std::path::Path;

    const IDENTITY: AuditIdentity = AuditIdentity {
        component_name: "apf-policy-gateway-middleware",
        enforcement_point_id: "apf-policy-gateway:middleware",
        runtime_substrate: "openshell",
        trust_root_id: "apf-policy-service:signing",
        version: "0.0.0-test",
    };

    fn records(dir: &Path) -> Vec<AuditEvent> {
        std::fs::read_to_string(dir.join("apf-policy-gateway-middleware-audit.jsonl"))
            .expect("audit log was written")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is one event"))
            .collect()
    }

    /// Credential probing against either listener left no trace at all: the
    /// request is refused before any RPC runs, so nothing downstream sees it.
    #[test]
    fn a_rejected_credential_is_recorded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = ComponentAudit::to_jsonl_in(dir.path(), IDENTITY).expect("emitter");
        let mut verifier = verifier(300, 0).with_audit(audit);

        let request = request_with_authorization("Bearer not-a-jwt");
        assert!(
            verifier.call(request).is_err(),
            "a malformed credential must be refused"
        );

        let r = &records(dir.path())[0];
        assert_eq!(r.event_type, apf_audit::EventType::Authentication);
        assert_eq!(
            r.reason_code.as_deref(),
            Some("extension_auth.credential_invalid")
        );
        assert_eq!(
            r.caller_kind, None,
            "nothing authenticated, so no kind is named"
        );
        assert_eq!(
            r.bundle_digest.as_deref(),
            None,
            "no policy was consulted, so the record names none"
        );
    }

    /// The token is attacker-supplied and unverified. Nothing derived from it
    /// may reach the record — the raw credential least of all.
    #[test]
    fn no_part_of_a_rejected_credential_reaches_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = ComponentAudit::to_jsonl_in(dir.path(), IDENTITY).expect("emitter");
        let mut verifier = verifier(300, 0).with_audit(audit);

        // Signed correctly but long expired: it reaches the claim checks, so
        // the verifier has decoded content it could leak.
        let token = sign(&gateway_claims(now_secs() - 86_400));
        let request = request_with_authorization(&format!("Bearer {token}"));
        assert!(verifier.call(request).is_err(), "expired must be refused");

        let line =
            std::fs::read_to_string(dir.path().join("apf-policy-gateway-middleware-audit.jsonl"))
                .expect("audit log");
        assert!(
            !line.contains(&token),
            "the credential must never be recorded: {line}"
        );
        for fragment in token.split('.') {
            assert!(
                !line.contains(fragment),
                "no token segment may be recorded: {fragment}"
            );
        }
        // Decoded claims, not just the encoded segments: logging `iss`, `sub`
        // or `jti` after verification would pass the checks above.
        for claim in ["openshell-gateway:test-gateway", "gateway-token"] {
            assert!(
                !line.contains(claim),
                "no decoded claim may be recorded: {claim}"
            );
        }
    }

    /// A caller kind the RPC does not permit is a different event from one that
    /// never authenticated — conflating them hides which check refused.
    #[test]
    fn authorization_failures_record_distinctly() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = ComponentAudit::to_jsonl_in(dir.path(), IDENTITY).expect("emitter");

        audit::emit_authorization_failure(&audit, AuthorizationFailure::MissingCaller, None)
            .expect("recorded");
        audit::emit_authorization_failure(
            &audit,
            AuthorizationFailure::CallerNotAllowed,
            Some(ExtensionCallerKind::Supervisor),
        )
        .expect("recorded");

        let records = records(dir.path());
        assert_eq!(
            records[0].reason_code.as_deref(),
            Some("extension_auth.caller_unauthenticated")
        );
        assert_eq!(records[0].caller_kind, None);
        assert_eq!(
            records[1].reason_code.as_deref(),
            Some("extension_auth.caller_not_allowed")
        );
        assert_eq!(
            records[1].caller_kind.as_deref(),
            Some("supervisor"),
            "the refused caller is named so a consumer can filter on it"
        );
    }

    /// Both kinds are live: a gateway can be refused on the supervisor-only
    /// egress RPC. A wrong mapping attributes a probe to the other component.
    #[test]
    fn every_caller_kind_records_under_its_own_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = ComponentAudit::to_jsonl_in(dir.path(), IDENTITY).expect("emitter");

        for kind in [
            ExtensionCallerKind::Gateway,
            ExtensionCallerKind::Supervisor,
        ] {
            audit::emit_authorization_failure(
                &audit,
                AuthorizationFailure::CallerNotAllowed,
                Some(kind),
            )
            .expect("recorded");
        }

        let records = records(dir.path());
        assert_eq!(records[0].caller_kind.as_deref(), Some("gateway"));
        assert_eq!(records[1].caller_kind.as_deref(), Some("supervisor"));
    }

    /// `CallerNotAllowed` without a caller would name a kind nothing proved.
    /// It degrades to the unauthenticated event rather than inventing one.
    #[test]
    fn a_refusal_with_no_caller_names_no_kind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = ComponentAudit::to_jsonl_in(dir.path(), IDENTITY).expect("emitter");

        audit::emit_authorization_failure(&audit, AuthorizationFailure::CallerNotAllowed, None)
            .expect("recorded");

        let r = &records(dir.path())[0];
        assert_eq!(r.caller_kind, None);
        assert_eq!(
            r.reason_code.as_deref(),
            Some("extension_auth.caller_unauthenticated")
        );
    }
}
