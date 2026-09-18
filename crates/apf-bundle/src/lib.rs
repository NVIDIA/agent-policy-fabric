// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod bundle;
pub mod counter_store;
pub mod manifest;
pub mod signing;
pub mod trust_store;
pub mod verifier;

pub use bundle::{
    Bundle, BundleMembers, BundleParseError, ManifestEntry, RuntimeCompatEntry, parse_bundle,
};
pub use counter_store::{CounterCheckError, CounterStore, CounterStoreError};
pub use manifest::{FindManifestError, find_bundle_manifest};
pub use signing::{Ed25519Signer, Ed25519Verifier, YamlSigilVerifier};
pub use trust_store::{TrustStore, TrustStoreError};
pub use verifier::{VerifyOutcome, verify_bundle};
