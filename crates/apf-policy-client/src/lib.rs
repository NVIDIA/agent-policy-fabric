// SPDX-License-Identifier: Apache-2.0
//! Thin gRPC client for the APF Policy Service.

use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub use apf_proto::policy_service_v1alpha1 as proto;

use apf_proto::runtime_v1alpha1::RuntimeContext;
use proto::policy_service_client::PolicyServiceClient;
use proto::{
    GetDocumentRequest, GetDocumentResponse, HealthRequest, HealthResponse, ListDocumentsRequest,
    ListDocumentsResponse,
};

#[derive(Debug, thiserror::Error)]
pub enum PolicyClientError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("call failed: {0}")]
    Call(#[from] tonic::Status),
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
}

#[derive(Clone)]
pub struct PolicyClientHandle {
    service: PolicyServiceClient<Channel>,
}

impl PolicyClientHandle {
    /// Build a handle from an existing tonic channel.
    #[must_use]
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            service: PolicyServiceClient::new(channel),
        }
    }

    /// Build a handle that is not connected to any APF Policy Service instance.
    ///
    /// All calls on this handle will fail. Intended for unit tests that do not
    /// exercise any APF RPC path.
    #[must_use]
    pub fn disconnected() -> Self {
        let channel = Channel::from_static("http://[::]:0").connect_lazy();
        Self::from_channel(channel)
    }

    /// Connect to a UDS-served APF Policy Service at `socket_path`.
    pub async fn connect<P: AsRef<Path>>(socket_path: P) -> Result<Self, PolicyClientError> {
        let path: PathBuf = socket_path.as_ref().to_path_buf();
        let endpoint = Endpoint::try_from("http://[::]:0")?
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5));
        let channel = endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(&path)
                        .await
                        .map_err(|e| std::io::Error::new(e.kind(), e.to_string()))?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| PolicyClientError::Connect(e.to_string()))?;
        Ok(Self::from_channel(channel))
    }

    /// Liveness probe.
    pub async fn health(&mut self) -> Result<HealthResponse, PolicyClientError> {
        let resp = self.service.health(HealthRequest {}).await?;
        Ok(resp.into_inner())
    }

    /// Returns the named governed document for `kind` (surface ID, e.g. `"apf.policy.v1"`).
    pub async fn get_document(
        &mut self,
        kind: impl Into<String>,
        name: impl Into<String>,
        context: Option<RuntimeContext>,
    ) -> Result<GetDocumentResponse, PolicyClientError> {
        let resp = self
            .service
            .get_document(GetDocumentRequest {
                kind: kind.into(),
                name: name.into(),
                runtime_context: context,
            })
            .await?;
        Ok(resp.into_inner())
    }

    /// Enumerates governed document names for `kind`.
    pub async fn list_documents(
        &mut self,
        kind: impl Into<String>,
    ) -> Result<ListDocumentsResponse, PolicyClientError> {
        let resp = self
            .service
            .list_documents(ListDocumentsRequest { kind: kind.into() })
            .await?;
        Ok(resp.into_inner())
    }
}
