// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
pub mod audit;
pub mod middleware;
pub mod patches;
pub use apf_openshell_auth::{
    AuthenticatedCaller, ExtensionAuthConfigError, ExtensionAuthVerifier, ExtensionCallerKind,
};
pub use middleware::{AuthenticatedSupervisorMiddlewareServer, SupervisorMiddlewareService};
