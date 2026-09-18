// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Shared event bus types for policy gateway background actors.

use tokio::sync::broadcast;

/// Events published on the policy gateway event bus.
#[derive(Debug, Clone)]
pub enum BundleEvent {
    /// The governed policy document's content digest changed.
    BundleChanged {
        /// New document digest reported by the policy service.
        digest: String,
        /// Millisecond epoch timestamp after which the projection expires,
        /// or 0 if no deadline is set.
        valid_until_ms: u64,
    },
}

/// Sending end of the bundle event bus.
pub type BundleEventSender = broadcast::Sender<BundleEvent>;

/// Receiving end of the bundle event bus.
pub type BundleEventReceiver = broadcast::Receiver<BundleEvent>;

/// Create a new bundle event channel with a capacity of 16 slots.
#[must_use]
pub fn bundle_event_channel() -> (BundleEventSender, BundleEventReceiver) {
    broadcast::channel(16)
}
