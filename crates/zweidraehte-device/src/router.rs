//! Outbox + dispatch table — the router-side primitives the runner
//! uses to thread messages between layers.
//!
//! Layers themselves live in [`crate::service`]. The
//! [`Outbox`] is the shared message queue every layer pushes into;
//! the runner drains it and dispatches each message to the layer
//! that owns it via the
//! [`DispatchTable`] (a `ServiceType` → field-index map built at
//! compile time inside each device's
//! [`LayerRegistry`](crate::service::LayerRegistry) impl).
//!
//! The link layer remains a separate async task, connected to the
//! router via the 3-channel interface (req/ind/conf).

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::{KnxMessageBuffer, ServiceType};

// ============================================================================
// Outbox
// ============================================================================

/// Maximum number of messages that can be in the outbox at once.
///
/// A full indication→response chain is about 6 hops (LL→NL→TL→AL→TL→NL→LL).
/// 8 provides headroom for side-outputs (e.g., TL pushing both an ACK and a
/// data indication simultaneously).
const OUTBOX_CAPACITY: usize = 8;

/// Collects output messages from layers.
///
/// Messages pushed here are dispatched by the router after the current
/// layer returns. Each message carries its own `ServiceType`, which
/// determines where it goes next.
pub struct Outbox {
    // Simple inline ring buffer to avoid heapless dependency for this.
    // Messages are pushed to the back and taken from the front.
    messages: [Option<KnxMessageBuffer<Buffer<'static>>>; OUTBOX_CAPACITY],
    /// Index of the next message to take.
    head: usize,
    /// Number of messages currently in the outbox.
    count: usize,
}

impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Outbox {
    /// Create a new empty outbox.
    pub fn new() -> Self {
        Self { messages: [const { None }; OUTBOX_CAPACITY], head: 0, count: 0 }
    }

    /// Push a message to the outbox.
    ///
    /// # Panics
    ///
    /// Panics if the outbox is full. This indicates a bug — legitimate
    /// message chains never produce more than ~6 messages in a single
    /// drain cycle.
    pub fn push(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        assert!(self.count < OUTBOX_CAPACITY, "Outbox overflow — possible dispatch loop");
        let tail = (self.head + self.count) % OUTBOX_CAPACITY;
        self.messages[tail] = Some(msg);
        self.count += 1;
    }

    /// Return `true` when the outbox has no messages queued.
    ///
    /// Used by async callers that need to wait for the stack to finish
    /// processing before mutating state — e.g., the conformance DUT's
    /// restart handler, which must let the router push the
    /// `A_Restart_Response` to the link layer before it wipes the
    /// individual address.
    pub fn is_fully_empty(&self) -> bool {
        self.count == 0
    }

    /// Take the next message from the outbox, if any.
    pub fn take_next(&mut self) -> Option<KnxMessageBuffer<Buffer<'static>>> {
        if self.count == 0 {
            return None;
        }
        let msg = self.messages[self.head].take();
        self.head = (self.head + 1) % OUTBOX_CAPACITY;
        self.count -= 1;
        msg
    }
}

// ============================================================================
// DispatchTable
// ============================================================================

/// Fixed-size lookup table: ServiceType → layer index.
///
/// Built at compile time inside each device's
/// [`LayerRegistry`](crate::service::LayerRegistry) impl by walking
/// every `#[service(handler)]` field's
/// [`service::Layer::HANDLES`](crate::service::Layer::HANDLES).
/// Each ServiceType maps to exactly one layer (or none).
pub struct DispatchTable {
    /// Maps ServiceType discriminant (u8) → layer index.
    /// `0xFF` means no layer is registered for that ServiceType.
    table: [u8; 256],
}

impl DispatchTable {
    /// Create an empty dispatch table with no registered layers.
    pub const fn empty() -> Self {
        Self { table: [0xFF; 256] }
    }

    /// Register a layer index for a ServiceType value.
    ///
    /// This is const-callable, enabling compile-time table construction.
    pub const fn register(&mut self, service_type: u8, layer_idx: u8) {
        // Catch duplicate registrations at compile time.
        // Must use `core::assert!` directly — the crate's `fmt.rs` remaps
        // `assert!`/`debug_assert!` to defmt equivalents on embedded targets,
        // which aren't const-compatible.
        core::assert!(self.table[service_type as usize] == 0xFF, "Duplicate layer registration for ServiceType");
        self.table[service_type as usize] = layer_idx;
    }

    /// Look up the layer index for a ServiceType.
    ///
    /// Returns `None` if no layer is registered.
    pub fn get(&self, st: ServiceType) -> Option<u8> {
        let raw: u8 = st.into();
        let idx = self.table[raw as usize];
        if idx == 0xFF { None } else { Some(idx) }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_push_and_take() {
        let mut outbox = Outbox::new();
        assert!(outbox.take_next().is_none());

        // We can't easily create Buffer<'static> in tests without a pool,
        // so we just test the None path and the structural logic.
        assert_eq!(outbox.count, 0);
    }

    #[test]
    fn dispatch_table_register_and_get() {
        let mut table = DispatchTable::empty();
        // Register two ServiceTypes to different field indices.
        table.register(ServiceType::L_Data_Ind.into(), 0);
        table.register(ServiceType::N_Data_Ind.into(), 1);

        assert_eq!(table.get(ServiceType::L_Data_Ind), Some(0));
        assert_eq!(table.get(ServiceType::N_Data_Ind), Some(1));
        assert_eq!(table.get(ServiceType::L_Data_Req), None);
    }
}
