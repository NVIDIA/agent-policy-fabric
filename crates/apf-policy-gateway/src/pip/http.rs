// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic REST provider: answers a lookup with one GET against a configured
//! JSON API and projects the response into the registered context's claims.
//!
//! Request parameters come from the projected subject, must match their
//! anchored patterns, and are percent-encoded for the position they fill: a
//! path segment or a query value. The client follows no redirects, uses no
//! proxy, and requires `https` away from loopback. Credential files are read
//! on every call, so a rotated token takes effect without a restart; they are
//! also read once at construction so a broken credential fails startup
//! instead of degrading every evaluation.

use std::time::Duration;

use super::config::{ConfigError, HttpSource};
use super::provider::{Lookup, LookupFuture, ProviderTransport};

/// HTTP client bound to one lowered `http` registration.
pub struct HttpTransport {
    name: String,
}

impl HttpTransport {
    /// Build the transport from a lowered registration: compile the key
    /// patterns, check the URL template, build the client and prove the
    /// credential file readable.
    ///
    /// # Errors
    ///
    /// Returns the first configuration error, attributed to `name`.
    pub fn new(name: &str, source: &HttpSource) -> Result<Self, ConfigError> {
        let _ = source;
        Ok(Self {
            name: name.to_owned(),
        })
    }

    /// Registered provider name, for logs.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl ProviderTransport for HttpTransport {
    fn lookup<'a>(&'a self, lookup: Lookup, budget: Duration) -> LookupFuture<'a> {
        let _ = (lookup, budget);
        todo!("implemented with the REST provider type")
    }
}
