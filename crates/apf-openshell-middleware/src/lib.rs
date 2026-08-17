// SPDX-License-Identifier: Apache-2.0
pub mod auth;
pub mod middleware;
pub mod patches;
pub use auth::{
    AuthenticatedCaller, ExtensionAuthConfigError, ExtensionAuthVerifier, ExtensionCallerKind,
};
pub use middleware::{AuthenticatedSupervisorMiddlewareServer, SupervisorMiddlewareService};
