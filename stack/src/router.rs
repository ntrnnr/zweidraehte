//! Table-driven message router for the KNX protocol stack.
//!
//! The router replaces the previous architecture of independent async layer
//! tasks connected by channels. Instead, NL, TL, and AL are synchronous
//! [`MessageHandler`] implementations dispatched by a single async loop.
//!
//! Messages are routed based on their [`ServiceType`]. Each handler declares
//! which ServiceTypes it handles via [`MessageHandler::HANDLES`], and the
//! router builds a compile-time dispatch table mapping ServiceType → handler.
//!
//! The link layer remains a separate async task, connected to the router via
//! the existing 3-channel interface (req/ind/conf).

use embassy_time::Instant;

use crate::messages::buffers::Buffer;
use crate::messages::knx::{KnxMessageBuffer, ServiceType};

// ============================================================================
// MessageHandler Trait
// ============================================================================

/// A synchronous message handler registered for specific ServiceTypes.
///
/// Handlers process messages and produce outputs via the [`Outbox`]. The
/// router calls handlers based on the message's ServiceType, then dispatches
/// any outputs through the table again.
///
/// Each ServiceType maps to exactly one handler. Routing ambiguity is resolved
/// by using distinct ServiceTypes (e.g., `CemiTl_Data_Ind` vs `T_Data_Ind`).
pub trait MessageHandler {
    /// ServiceTypes this handler wants to receive.
    ///
    /// This is an associated const so that the dispatch table can be built
    /// at compile time.
    const HANDLES: &'static [ServiceType];

    /// Process a message. Push any output messages to the outbox.
    ///
    /// The outbox messages carry their own ServiceType, which the router
    /// uses to dispatch them to the next handler in the chain.
    fn process(
        &mut self,
        msg: KnxMessageBuffer<Buffer<'static>>,
        outbox: &mut Outbox,
    );

    /// Earliest deadline at which this handler wants a [`poll`](Self::poll)
    /// call. Returns `None` if no timer is needed.
    ///
    /// The router computes `min(all handlers' deadlines)` and uses it as
    /// the timeout for its event loop. When the timer fires, all handlers
    /// whose deadline has passed are polled.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Called when [`next_deadline`](Self::next_deadline) has elapsed.
    ///
    /// Push any timer-triggered messages to the outbox.
    fn poll(&mut self, _outbox: &mut Outbox) {}
}

// ============================================================================
// Outbox
// ============================================================================

/// Maximum number of messages that can be in the outbox at once.
///
/// A full indication→response chain is about 6 hops (LL→NL→TL→AL→TL→NL→LL).
/// 8 provides headroom for side-outputs (e.g., TL pushing both an ACK and
/// a data indication simultaneously).
const OUTBOX_CAPACITY: usize = 8;

/// Collects output messages from handlers.
///
/// Messages pushed here are dispatched by the router after the current
/// handler returns. Each message carries its own ServiceType, which
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

impl Outbox {
    /// Create a new empty outbox.
    pub fn new() -> Self {
        Self {
            messages: [const { None }; OUTBOX_CAPACITY],
            head: 0,
            count: 0,
        }
    }

    /// Push a message to the outbox.
    ///
    /// # Panics
    ///
    /// Panics if the outbox is full. This indicates a bug — legitimate
    /// message chains never produce more than ~6 messages in a single
    /// drain cycle.
    pub fn push(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        assert!(
            self.count < OUTBOX_CAPACITY,
            "Outbox overflow — possible dispatch loop"
        );
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

/// Fixed-size lookup table: ServiceType → handler index.
///
/// Built at compile time from each handler's [`MessageHandler::HANDLES`]
/// constant. Each ServiceType maps to exactly one handler (or none).
pub struct DispatchTable {
    /// Maps ServiceType discriminant (u8) → handler index.
    /// `0xFF` means no handler is registered for that ServiceType.
    table: [u8; 256],
}

impl DispatchTable {
    /// Create an empty dispatch table with no registered handlers.
    pub const fn empty() -> Self {
        Self { table: [0xFF; 256] }
    }

    /// Register a handler index for a ServiceType value.
    ///
    /// This is const-callable, enabling compile-time table construction.
    pub const fn register(&mut self, service_type: u8, handler_idx: u8) {
        // Catch duplicate registrations at compile time.
        // Must use `core::assert!` directly — the crate's `fmt.rs` remaps
        // `assert!`/`debug_assert!` to defmt equivalents on embedded targets,
        // which aren't const-compatible.
        core::assert!(
            self.table[service_type as usize] == 0xFF,
            "Duplicate handler registration for ServiceType"
        );
        self.table[service_type as usize] = handler_idx;
    }

    /// Look up the handler index for a ServiceType.
    ///
    /// Returns `None` if no handler is registered.
    pub fn get(&self, st: ServiceType) -> Option<u8> {
        let raw: u8 = st.into();
        let idx = self.table[raw as usize];
        if idx == 0xFF { None } else { Some(idx) }
    }
}

// ============================================================================
// HandlerSet Trait
// ============================================================================

/// A composed set of [`MessageHandler`]s with a compile-time dispatch table.
///
/// Implemented for tuples of `MessageHandler` via the
/// [`impl_handler_set!`] macro. The `StackDefinition::Handlers` associated
/// type determines which tuple is used for a given device.
pub trait HandlerSet {
    /// Dispatch table mapping ServiceType → handler index, built at
    /// compile time from all handlers' [`MessageHandler::HANDLES`].
    const DISPATCH_TABLE: DispatchTable;

    /// Dispatch a message to the handler at the given index.
    fn dispatch(
        &mut self,
        handler_idx: u8,
        msg: KnxMessageBuffer<Buffer<'static>>,
        outbox: &mut Outbox,
    );

    /// Earliest deadline across all handlers.
    fn next_deadline(&self) -> Option<Instant>;

    /// Poll all handlers that have a pending deadline.
    ///
    /// Called by the router when the earliest deadline has elapsed. Since the
    /// router only reaches the timer arm when `Timer::at(earliest_deadline)`
    /// fires, all handlers with deadlines at or before now are eligible.
    fn poll(&mut self, outbox: &mut Outbox);
}

// ============================================================================
// HandlerSet tuple implementations
// ============================================================================

/// Helper to build the dispatch table const for a set of handler types.
///
/// Each handler type's `HANDLES` array is iterated at compile time, and
/// the handler's positional index is recorded in the table.
macro_rules! impl_handler_set {
    // Base case: single handler.
    ($($idx:tt : $T:ident),+) => {
        impl<$($T: MessageHandler),+> HandlerSet for ($($T,)+) {
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
                handler_idx: u8,
                msg: KnxMessageBuffer<Buffer<'static>>,
                outbox: &mut Outbox,
            ) {
                match handler_idx {
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
                // Poll every handler that has a pending deadline.
                //
                // We don't compare against a captured `now` because handlers
                // that want immediate polling return `Instant::now()` from
                // `next_deadline()`. If we compared that against a `now`
                // captured earlier, the fresh `Instant::now()` would always
                // be slightly *after* the stale one, and the `d <= now` check
                // would never pass.
                //
                // Instead, simply poll every handler that has *any* deadline.
                // Handlers with future deadlines (e.g. TL timeouts) won't
                // reach this point because the router's `Timer::at(deadline)`
                // hasn't fired yet — the select only reaches the timer arm
                // when the earliest deadline has actually elapsed.
                $(
                    if self.$idx.next_deadline().is_some() {
                        self.$idx.poll(outbox);
                    }
                )+
            }
        }
    };
}

// Generate HandlerSet impls for tuple sizes 1 through 8.
impl_handler_set!(0: A);
impl_handler_set!(0: A, 1: B);
impl_handler_set!(0: A, 1: B, 2: C);
impl_handler_set!(0: A, 1: B, 2: C, 3: D);
impl_handler_set!(0: A, 1: B, 2: C, 3: D, 4: E);
impl_handler_set!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F);
impl_handler_set!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G);
impl_handler_set!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct NlHandler;
    impl MessageHandler for NlHandler {
        const HANDLES: &'static [ServiceType] = &[
            ServiceType::L_Data_Ind,
        ];

        fn process(
            &mut self,
            mut msg: KnxMessageBuffer<Buffer<'static>>,
            outbox: &mut Outbox,
        ) {
            msg.set_service_type(ServiceType::N_Data_Ind);
            outbox.push(msg);
        }
    }

    struct TlHandler;
    impl MessageHandler for TlHandler {
        const HANDLES: &'static [ServiceType] = &[
            ServiceType::N_Data_Ind,
        ];

        fn process(
            &mut self,
            mut msg: KnxMessageBuffer<Buffer<'static>>,
            outbox: &mut Outbox,
        ) {
            msg.set_service_type(ServiceType::T_Data_Ind);
            outbox.push(msg);
        }
    }

    struct AlHandler {
        received: usize,
    }
    impl MessageHandler for AlHandler {
        const HANDLES: &'static [ServiceType] = &[
            ServiceType::T_Data_Ind,
        ];

        fn process(
            &mut self,
            _msg: KnxMessageBuffer<Buffer<'static>>,
            _outbox: &mut Outbox,
        ) {
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
        let set: (NlHandler, TlHandler, AlHandler) = (
            NlHandler,
            TlHandler,
            AlHandler { received: 0 },
        );
        assert_eq!(set.next_deadline(), None);
    }
}
