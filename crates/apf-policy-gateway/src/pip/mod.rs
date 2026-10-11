// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy information providers: the enrichment stage of the gateway's
//! decision pipeline.
//!
//! Providers are registered from a deployment-owned file. Before the policy
//! engine runs, [`ProviderContextEnricher`] projects the evaluation subject to
//! the fields each applicable provider is registered to receive, looks the
//! attributes up over the provider's transport within a budget, validates the
//! answer, stamps provenance, and writes the result into the evaluator input
//! as `context.<context>`. The stage knows nothing about the policy language;
//! the engine adapter maps the namespaces into its own context.
//!
//! Transports: the `PolicyInformationService` contract over HTTPS with mutual
//! TLS or over a Unix domain socket ([`grpc`]), and a generic REST provider
//! that turns an existing JSON API into a provider by configuration
//! ([`http`]).

pub mod config;
pub mod enricher;
pub mod grpc;
pub mod http;
pub mod provider;
pub mod subject;

pub use config::{
    ConfigError, Endpoint, EndpointKind, FailureMode, HttpAuth, HttpParam, HttpSource, Keep,
    KeySpec, Limits, MatchSpec, ProviderKind, ProviderRegistration, RegistryConfig, Request,
    Response, TlsConfig, Trigger,
};
pub use enricher::{ProviderContextEnricher, RegisteredProvider};
pub use provider::{
    Attributes, Lookup, LookupFuture, LookupResult, ProviderError, ProviderTransport,
    authorize_peer, check_value, validate_response,
};
pub use subject::SubjectPath;
