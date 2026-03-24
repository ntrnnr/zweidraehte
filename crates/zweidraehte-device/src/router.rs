//! Table-driven message router for the KNX protocol stack.
//!
//! The router replaces the previous architecture of independent async layer
//! tasks connected by channels. Instead, NL, TL, and AL are synchronous
//! [`Layer`] implementations dispatched by a single async loop.
//!
//! Messages are routed based on their [`ServiceType`]. Each layer declares
//! which ServiceTypes it handles via [`Layer::HANDLES`], and the
//! router builds a compile-time dispatch table mapping ServiceType → layer.
//!
//! The link layer remains a separate async task, connected to the router via
//! the existing 3-channel interface (req/ind/conf).

use embassy_time::Instant;

use crate::messages::buffers::Buffer;
use crate::messages::knx::{KnxMessageBuffer, ServiceType};

// ============================================================================
// Layer Trait
// ============================================================================

/// A synchronous protocol layer registered for specific ServiceTypes.
///
/// Layers process messages and produce outputs via the [`Outbox`]. The
/// router calls layers based on the message's ServiceType, then dispatches
/// any outputs through the table again.
///
/// Each ServiceType maps to exactly one layer. Routing ambiguity is resolved
/// by using distinct ServiceTypes (e.g., `CemiTl_Data_Ind` vs `T_Data_Ind`).
pub trait Layer {
    /// ServiceTypes this layer wants to receive.
    ///
    /// This is an associated const so that the dispatch table can be built
    /// at compile time.
    const HANDLES: &'static [ServiceType];

    /// Process a message. Push any output messages to the outbox.
    ///
    /// The outbox messages carry their own ServiceType, which the router
    /// uses to dispatch them to the next layer in the chain.
    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox);

    /// Earliest deadline at which this layer wants a [`poll`](Self::poll)
    /// call. Returns `None` if no timer is needed.
    ///
    /// The router computes `min(all layers' deadlines)` and uses it as
    /// the timeout for its event loop. When the timer fires, all layers
    /// whose deadline has passed are polled.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Called when [`next_deadline`](Self::next_deadline) has elapsed.
    ///
    /// Push any timer-triggered messages to the outbox.
    fn poll(&mut self, _outbox: &mut Outbox) {}

    /// One-time initialization called after layer construction but before
    /// the router loop starts.
    ///
    /// Use this for setup that depends on runtime state (e.g., checking
    /// whether the application is already running and starting a read-on-init
    /// cycle). Default is a no-op.
    fn init(&mut self) {}
}

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
/// layer returns. Each message carries its own ServiceType, which
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
/// Built at compile time from each layer's [`Layer::HANDLES`]
/// constant. Each ServiceType maps to exactly one layer (or none).
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
// LayerStack Trait
// ============================================================================

/// A composed set of [`Layer`]s with a compile-time dispatch table.
///
/// Implemented for tuples of `Layer` via the
/// [`impl_layer_stack!`] macro. The [`LayerStackBuilder::Stack`](crate::LayerStackBuilder::Stack)
/// associated type determines which tuple is used for a given device.
pub trait LayerStack {
    /// Dispatch table mapping ServiceType → layer index, built at
    /// compile time from all layers' [`Layer::HANDLES`].
    const DISPATCH_TABLE: DispatchTable;

    /// Dispatch a message to the layer at the given index.
    fn dispatch(&mut self, layer_idx: u8, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox);

    /// Earliest deadline across all layers.
    fn next_deadline(&self) -> Option<Instant>;

    /// Poll all layers that have a pending deadline.
    ///
    /// Called by the router when the earliest deadline has elapsed. Since the
    /// router only reaches the timer arm when `Timer::at(earliest_deadline)`
    /// fires, all layers with deadlines at or before now are eligible.
    fn poll(&mut self, outbox: &mut Outbox);

    /// Initialize all layers. Called once before the router loop starts.
    fn init(&mut self);

    /// Wait for external (non-dispatch-table) input.
    ///
    /// The router `select`s on this future alongside LL events and
    /// layer timers. When it resolves, the router calls
    /// [`handle_side_input`](Self::handle_side_input).
    ///
    /// Default: pends forever (no external input).
    fn recv_side_input(&self) -> impl core::future::Future<Output = ()> + '_ {
        core::future::pending()
    }

    /// Process the external input that [`recv_side_input`](Self::recv_side_input)
    /// signaled.
    ///
    /// Called immediately after `recv_side_input` resolves. Push any
    /// resulting messages to the outbox.
    ///
    /// Default: no-op.
    fn handle_side_input(&mut self, _outbox: &mut Outbox) {}

    /// Drain and handle [`StackEvent`]s emitted by layers during this
    /// dispatch cycle.
    ///
    /// Called by the runner after the message drain loop completes.
    /// Composition layers override this to forward events to the
    /// [`DeviceModel`](crate::device_model::DeviceModel).
    ///
    /// Default: no-op (plain tuple layer stacks have no event handler).
    fn drain_events(&mut self, _outbox: &mut Outbox) {}
}

// ============================================================================
// LayerStack tuple implementations
// ============================================================================

/// Helper to build the dispatch table const for a set of layer types.
///
/// Each layer type's `HANDLES` array is iterated at compile time, and
/// the layer's positional index is recorded in the table.
macro_rules! impl_layer_stack {
    // Base case: single layer.
    ($($idx:tt : $T:ident),+) => {
        impl<$($T: Layer),+> LayerStack for ($($T,)+) {
            const DISPATCH_TABLE: DispatchTable = {
                let mut table = DispatchTable::empty();
                $(
                    {
                        let mut i = 0;
                        while i < $T::HANDLES.len() {
                            let st: u8 = $T::HANDLES[i].into();
                            table.register(st, $idx);
                            i += 1;
                        }
                    }
                )+
                table
            };

            fn dispatch(
                &mut self,
                layer_idx: u8,
                msg: KnxMessageBuffer<Buffer<'static>>,
                outbox: &mut Outbox,
            ) {
                match layer_idx {
                    $($idx => self.$idx.process(msg, outbox),)+
                    _ => unreachable!(),
                }
            }

            fn next_deadline(&self) -> Option<Instant> {
                let mut earliest: Option<Instant> = None;
                $(
                    if let Some(d) = self.$idx.next_deadline() {
                        earliest = Some(match earliest {
                            Some(e) if e < d => e,
                            _ => d,
                        });
                    }
                )+
                earliest
            }

            fn poll(&mut self, outbox: &mut Outbox) {
                // Poll every layer that has a pending deadline.
                //
                // We don't compare against a captured `now` because layers
                // that want immediate polling return `Instant::now()` from
                // `next_deadline()`. If we compared that against a `now`
                // captured earlier, the fresh `Instant::now()` would always
                // be slightly *after* the stale one, and the `d <= now` check
                // would never pass.
                //
                // Instead, simply poll every layer that has *any* deadline.
                // Layers with future deadlines (e.g. TL timeouts) won't
                // reach this point because the router's `Timer::at(deadline)`
                // hasn't fired yet — the select only reaches the timer arm
                // when the earliest deadline has actually elapsed.
                $(
                    if self.$idx.next_deadline().is_some() {
                        self.$idx.poll(outbox);
                    }
                )+
            }

            fn init(&mut self) {
                $(self.$idx.init();)+
            }
        }
    };
}

// Generate LayerStack impls for tuple sizes 1 through 8.
impl_layer_stack!(0: A);
impl_layer_stack!(0: A, 1: B);
impl_layer_stack!(0: A, 1: B, 2: C);
impl_layer_stack!(0: A, 1: B, 2: C, 3: D);
impl_layer_stack!(0: A, 1: B, 2: C, 3: D, 4: E);
impl_layer_stack!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F);
impl_layer_stack!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G);
impl_layer_stack!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H);

// ============================================================================
// ExtraSideInput — composable side-input extensions
// ============================================================================

/// Composable side-input extension for [`LayerStack`] implementations.
///
/// Side inputs inject events into the router loop from outside the dispatch
/// table — sources that don't map to a [`ServiceType`] in the normal
/// dispatch flow. `ExtraSideInput` is parameterised over the concrete
/// layer tuple so that the handler has typed access to individual layers.
///
/// `Layers` is the concrete layer tuple, giving the handler typed access
/// to call specific layer methods (e.g., `layers.1.handle_cemi_event()`).
///
/// # Contract
///
/// - [`recv`](Self::recv) is called from `select` and must buffer the
///   incoming event internally (e.g., via `Cell`) because the `LayerStack`
///   is immutably borrowed during the async wait.
/// - [`handle`](Self::handle) is called synchronously after `recv` resolves,
///   with `&mut` access to both `self` and the layer tuple.
pub trait ExtraSideInput<Layers> {
    /// Wait for and buffer the next event.
    ///
    /// Called inside the router's `select` alongside the app service
    /// receiver and timer. Use `Cell` or similar interior mutability to
    /// store the received event, since `&self` is shared.
    fn recv(&self) -> impl core::future::Future<Output = ()> + '_;

    /// Process the buffered event.
    ///
    /// Called immediately after [`recv`](Self::recv) resolves. Push any
    /// resulting messages to the outbox.
    fn handle(&mut self, layers: &mut Layers, outbox: &mut Outbox);
}

/// No extra side inputs — pends forever on recv, no-op on handle.
impl<L> ExtraSideInput<L> for () {
    fn recv(&self) -> impl core::future::Future<Output = ()> + '_ {
        core::future::pending()
    }

    fn handle(&mut self, _layers: &mut L, _outbox: &mut Outbox) {}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct NlHandler;
    impl Layer for NlHandler {
        const HANDLES: &'static [ServiceType] = &[ServiceType::L_Data_Ind];

        fn process(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
            msg.set_service_type(ServiceType::N_Data_Ind);
            outbox.push(msg);
        }
    }

    struct TlHandler;
    impl Layer for TlHandler {
        const HANDLES: &'static [ServiceType] = &[ServiceType::N_Data_Ind];

        fn process(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
            msg.set_service_type(ServiceType::T_Data_Ind);
            outbox.push(msg);
        }
    }

    struct AlHandler {
        received: usize,
    }
    impl Layer for AlHandler {
        const HANDLES: &'static [ServiceType] = &[ServiceType::T_Data_Ind];

        fn process(&mut self, _msg: KnxMessageBuffer<Buffer<'static>>, _outbox: &mut Outbox) {
            // Terminal — consume the message, don't push anything.
            self.received += 1;
        }
    }

    #[test]
    fn dispatch_table_is_built_correctly() {
        type TestSet = (NlHandler, TlHandler, AlHandler);
        let table = &TestSet::DISPATCH_TABLE;

        assert_eq!(table.get(ServiceType::L_Data_Ind), Some(0));
        assert_eq!(table.get(ServiceType::N_Data_Ind), Some(1));
        assert_eq!(table.get(ServiceType::T_Data_Ind), Some(2));
        // Unregistered types return None
        assert_eq!(table.get(ServiceType::L_Data_Req), None);
    }

    #[test]
    fn outbox_push_and_take() {
        let mut outbox = Outbox::new();
        assert!(outbox.take_next().is_none());

        // We can't easily create Buffer<'static> in tests without a pool,
        // so we just test the None path and the structural logic.
        assert_eq!(outbox.count, 0);
    }

    #[test]
    fn handler_set_next_deadline_returns_earliest() {
        // NlHandler and TlHandler have no deadlines (return None).
        // AlHandler also has no deadline.
        let set: (NlHandler, TlHandler, AlHandler) = (NlHandler, TlHandler, AlHandler { received: 0 });
        assert_eq!(set.next_deadline(), None);
    }
}
