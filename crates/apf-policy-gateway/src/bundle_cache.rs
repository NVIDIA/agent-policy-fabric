// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use apf_bundle::{BundleMembers, CounterStore, verify_bundle};
use apf_types::BundleVerifier;

/// Verify and parse a raw bundle from `bytes`, returning the members on success.
///
/// `verifier` performs signature verification (e.g. `Ed25519Verifier`).
/// `counter_store` enforces monotonic-counter rollback protection.
pub fn refresh(
    bytes: &[u8],
    path: &Path,
    verifier: &dyn BundleVerifier,
    counter_store: &CounterStore,
    runtime_versions: &HashMap<&str, &str>,
) -> anyhow::Result<BundleMembers> {
    let outcome = verify_bundle(
        bytes,
        path,
        verifier,
        counter_store,
        SystemTime::now(),
        runtime_versions,
    );
    if !outcome.ok {
        anyhow::bail!(
            "bundle verification failed: {:?}",
            outcome.rejection_reasons
        );
    }
    // Use the already-parsed Bundle from VerifyOutcome — avoids re-parsing the
    // raw artifact bytes which contain the yaml-sigil signature carrier.
    let bundle = outcome.bundle.expect("outcome.ok guarantees bundle is present");
    let members = bundle
        .load_members(path.parent().unwrap_or(Path::new(".")))
        .map_err(|e| anyhow::anyhow!("bundle member load failed: {e}"))?;
    Ok(members)
}
