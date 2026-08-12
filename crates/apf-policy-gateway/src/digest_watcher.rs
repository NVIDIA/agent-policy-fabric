// SPDX-License-Identifier: Apache-2.0
// Digest watcher: polls the policy service for the governed policy document digest
// and publishes BundleChanged events when the digest changes.

use std::time::Duration;

use tracing::{info, warn};

use apf_policy_client::PolicyClientHandle;
use apf_types::events::{BundleEvent, BundleEventSender};

/// Configuration for the policy document digest watcher.
pub struct DigestWatcherConfig {
    /// Surface ID passed to `GetDocument`.
    pub document_kind: String,
    /// Document name passed to `GetDocument`.
    pub document_name: String,
    /// How often to poll the policy service for the document digest.
    pub interval: Duration,
}

/// Spawn a background task that polls the policy service at `config.interval` for
/// the governed policy document digest. The first successful poll sets the
/// baseline without emitting an event. Each subsequent poll where the digest
/// differs from the baseline publishes a `BundleChanged` event on `tx`. On
/// poll failure a warning is logged and the task continues from the existing
/// baseline.
pub fn spawn_digest_watcher(
    config: DigestWatcherConfig,
    mut policy_service: PolicyClientHandle,
    tx: BundleEventSender,
) {
    tokio::spawn(async move {
        let mut last_digest: Option<String> = None;
        loop {
            tokio::time::sleep(config.interval).await;

            let doc = match policy_service
                .get_document(
                    config.document_kind.as_str(),
                    config.document_name.as_str(),
                    None,
                )
                .await
            {
                Ok(doc) => doc,
                Err(e) => {
                    warn!(error = %e, "digest watcher: get_document failed");
                    continue;
                }
            };

            match last_digest.as_deref() {
                None => {
                    // First successful poll — establish baseline, no event.
                    last_digest = Some(doc.digest);
                }
                Some(prev) if prev == doc.digest => {
                    // Digest unchanged; nothing to do.
                }
                Some(_) => {
                    info!(
                        digest = %doc.digest,
                        valid_until_ms = doc.valid_until_ms,
                        "policy document digest changed; publishing BundleChanged"
                    );
                    let event = BundleEvent::BundleChanged {
                        digest: doc.digest.clone(),
                        valid_until_ms: doc.valid_until_ms,
                    };
                    if tx.send(event).is_err() {
                        // All receivers dropped; the gateway is shutting down.
                        break;
                    }
                    last_digest = Some(doc.digest);
                }
            }
        }
    });
}
