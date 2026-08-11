// SPDX-License-Identifier: Apache-2.0
// Shared event bus for interceptor background actors.

use tokio::sync::broadcast;

/// Events published on the interceptor-internal bus.
#[derive(Debug, Clone)]
pub enum InterceptorEvent {
    /// The governed policy document's content digest changed.
    BundleChanged {
        /// New document digest reported by the policy service.
        digest: String,
        /// Millisecond epoch timestamp after which the projection expires,
        /// or 0 if no deadline is set. Used by the sandbox refresher to arm
        /// a proactive refresh before the deadline.
        valid_until_ms: u64,
    },
}

/// Sending end of the interceptor event bus.
pub type EventSender = broadcast::Sender<InterceptorEvent>;

/// Receiving end of the interceptor event bus.
pub type EventReceiver = broadcast::Receiver<InterceptorEvent>;

/// Create a new event channel with a capacity of 16 slots.
///
/// A capacity of 16 is sufficient for any realistic burst of digest changes
/// before the subscribers drain the queue.
#[must_use]
pub fn event_channel() -> (EventSender, EventReceiver) {
    broadcast::channel(16)
}
