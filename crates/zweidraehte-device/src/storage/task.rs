//! The generic storage task: one body, every device.
//!
//! The router persists every configuration change itself, before the
//! response to it leaves the device ([`ConfigFlush`], write-through). What
//! remains for a task is the work that must not run inside a dispatch:
//!
//! - **Restart requests** (the application layer's A_Restart handler on
//!   `restart_channel`): apply the erase code, flush what it changed, reset
//!   the device.
//! - **A periodic tick** ([`STORAGE_TICK`]): retry a flush that failed and
//!   left the state dirty (without it, a failure with no later traffic would
//!   stay pending), and compact a log store that asks for it
//!   ([`ConfigFlush::needs_compaction`]) behind the [`SaveGuard`], so a TP1
//!   device's bus stays answered during the long erase.
//!
//! The IP Secure mc_timer watermark is **not** handled here: its durability
//! ordering is synchronous, so the KNX/IP Secure link layer writes its store
//! directly through the storage handle on its context.
//!
//! Devices spawn it through the `storage_task!` macro (which emits the
//! monomorphic embassy wrapper — embassy tasks can't be generic).

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Ticker, Timer};

use zweidraehte_platform::SystemControl;

use crate::definition::StackDefinition;
use crate::restart::RestartType;
use crate::stack_handle::Stack;
use crate::state::HasPersistence;
use crate::timing::time_divisor;

use super::{ConfigFlush, StorageHooks};

/// How often the task retries a pending flush and checks whether the store
/// wants compacting. Cheap when there is nothing to do (a `Cell` read and a
/// fill-level check).
pub const STORAGE_TICK: Duration = Duration::from_secs(1);

/// Pause between applying a restart and pulling the reset line.
///
/// Empirical, not spec-derived: long enough for the already-queued
/// A_Restart_Response to leave the link layer (and, on TP1, for the remote
/// TL's retry window to see it) before the device disappears from the bus.
///
/// This is the wall-clock value; conformance builds compress it — see
/// [`restart_settle_delay`].
pub const RESTART_SETTLE_DELAY: Duration = Duration::from_millis(100);

/// [`RESTART_SETTLE_DELAY`] scaled by [`time_divisor`].
///
/// The delay measures a *bus* interval — how long the response needs to get
/// clear of the device — so it compresses with the rest of the bus timing in
/// a fast-mode run. Left unscaled it would add its full 100 ms to every
/// restart in a suite whose other timings run 50× faster, and a harness that
/// watches for the device going away would be left waiting through it.
fn restart_settle_delay() -> Duration {
    Duration::from_millis(RESTART_SETTLE_DELAY.as_millis() / time_divisor())
}

/// Cap on waiting for the router outbox to drain before applying an erase
/// code.
///
/// The wait itself is mandatory (see the restart arm below); the cap only
/// bounds it so a wedged outbox cannot make the device unrestartable. Far
/// above the normal case — the response is one frame, dispatched on the
/// router's next poll.
pub const OUTBOX_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

// ============================================================================
// SaveGuard — optional protection wrapped around each blocking flash save
// ============================================================================

/// A protection raised around the (executor-stalling) flash work inside the
/// storage task: compacting a log, and the flush after a restart's erase.
///
/// A flash erase/write takes tens of milliseconds and on the embedded targets
/// stalls the whole executor (RP2040 disables XIP; single-bank STM32 stalls
/// flash fetches), so a **TP1** device cannot answer the ~1.7 ms TP1 ACK window
/// during a save. Such a device passes a guard that arms the link layer's busy
/// protections (the software busy flag + the transceiver's autonomous BUSY mode)
/// before the stall and lowers them after — see `embedded-common`'s `BusyGate`.
///
/// Devices whose saves do **not** stall the link layer (KNX/IP, RF) pass
/// [`NoSaveGuard`], whose `acquire`/`release` compile away to nothing.
///
/// `acquire` is async (arming the chip is a request/response rendezvous) and the
/// returned guard's `release` is async too; the storage task `await`s both
/// around the awaited `save_config` call. `release` is explicit (there is
/// no async `Drop`) — the task always calls it on the path that acquired.
// `async fn` (not `-> impl Future + Send`): the storage task runs on a
// single-threaded embassy executor, so no `Send` bound is wanted — the lint's
// suggested workaround would impose one we'd then have to fight.
#[allow(async_fn_in_trait)]
pub trait SaveGuard {
    /// The raised-guard token returned by [`acquire`](Self::acquire).
    type Guard: SaveGuardToken;
    /// Raise the guard; after this resolves it is safe to stall the executor.
    async fn acquire(&self) -> Self::Guard;
}

/// The raised-guard token; [`release`](Self::release) lowers the guard.
#[allow(async_fn_in_trait)]
pub trait SaveGuardToken {
    /// Lower the guard once the blocking save has completed.
    async fn release(self);
}

/// The no-op [`SaveGuard`] for devices whose saves don't stall the link layer
/// (KNX/IP, RF). Both `acquire` and `release` compile away.
pub struct NoSaveGuard;

impl SaveGuard for NoSaveGuard {
    type Guard = ();
    async fn acquire(&self) -> Self::Guard {}
}

impl SaveGuardToken for () {
    async fn release(self) {}
}

// ============================================================================
// storage_task
// ============================================================================

/// Drive a device's storage work: restart requests and the periodic tick.
///
/// - A [`RestartRequest`](crate::restart::RestartRequest) first lets the
///   router outbox drain (the application layer queues the A_Restart_Response
///   *before* the request, and the network layer stamps its source address
///   only on the way out — erasing earlier sends the response from the
///   default individual address), announces the restart
///   ([`StorageHooks::on_restart`] — a no-op unless something outside the
///   device is watching), then applies the erase code to the runtime
///   state ([`HasPersistence::apply_erase_code`], master resets only) and the durable regions
///   ([`StorageHooks::erase`] — mc_timer clear + sending-SeqNr exhaustion
///   re-init on factory codes), flushes the result until it is durable,
///   waits [`RESTART_SETTLE_DELAY`], and resets via [`SystemControl`].
/// - The tick flushes a state still dirty after a failed router flush, then
///   compacts the store if it asks. Both compile away for a storage handle
///   without write-through ([`ConfigFlush::ENABLED`] false).
pub async fn storage_task<D, S, G>(knx: Stack<'static, D>, mut system: S, guard: G) -> !
where
    D: StackDefinition,
    D::Storage: StorageHooks + ConfigFlush<D::State>,
    S: SystemControl,
    G: SaveGuard,
{
    let mut tick = Ticker::every(STORAGE_TICK);
    loop {
        match select(knx.receive_restart_request(), tick.next()).await {
            Either::First(request) => {
                restart(knx, request, &mut system, &guard).await;
            }
            Either::Second(()) => {
                if <D::Storage as ConfigFlush<D::State>>::ENABLED {
                    let _ = knx.flush_pending_config();
                    knx.publish_status();
                    compact_if_needed(knx, &guard).await;
                }
            }
        }
    }
}

/// Compact a write-through store that asks for it, under the [`SaveGuard`].
///
/// A log store compacts by itself when an append finds its bank full, but
/// that happens inside a router flush, where the bus is not held busy.
/// Compacting here first, once the log passes its threshold, keeps the long
/// erase-and-rewrite behind the guard. Stores without history never ask.
async fn compact_if_needed<D, G>(knx: Stack<'static, D>, guard: &G)
where
    D: StackDefinition,
    D::Storage: ConfigFlush<D::State>,
    G: SaveGuard,
{
    let storage = knx.storage();
    if !storage.needs_compaction() {
        return;
    }
    let token = guard.acquire().await;
    if storage.compact(knx.state()).is_err() {
        crate::logging::warn!("config compaction failed; the log compacts on its next full bank");
    }
    token.release().await;
}

/// Apply an accepted restart and keep retrying until its changes are durable.
///
/// Drain before erasing so the response retains the old source address. Erase
/// hooks run once; retrying a failed flush must not repeatedly reset live
/// state. A failed platform reset returns to the caller after clearing
/// restart status.
pub async fn restart<D, S, G>(
    knx: Stack<'static, D>,
    request: crate::restart::RestartRequest,
    system: &mut S,
    guard: &G,
) where
    D: StackDefinition,
    D::Storage: StorageHooks + ConfigFlush<D::State>,
    S: SystemControl,
    G: SaveGuard,
{
    let context = knx.inner.layer_context;
    let storage = knx.storage();

    context.restarting.set(true);
    knx.publish_status();

    let _ = select(knx.await_outbox_drained(), Timer::after(OUTBOX_DRAIN_TIMEOUT)).await;

    storage.on_restart(request.restart).await;
    // A basic restart erases nothing; only a master reset has an erase code.
    if let RestartType::MasterReset(erase_code) = request.restart {
        knx.state().apply_erase_code(erase_code);
        storage.erase(erase_code);
    }
    knx.publish_status();

    loop {
        // The flush compares every Record with its durable copy, so it also
        // catches state that ordinary dirty tracking leaves out, such as the
        // security failure counters. An erase touches many sections, and the
        // appends may compact the log: keep the bus guarded throughout.
        let token = guard.acquire().await;
        let flushed = knx.flush_config();
        token.release().await;
        knx.publish_status();
        if flushed.is_err() {
            Timer::after(STORAGE_TICK).await;
            continue;
        }

        Timer::after(restart_settle_delay()).await;

        if knx.state().is_dirty() {
            continue;
        }

        let _ = system.restart().await;

        context.restarting.set(false);
        knx.publish_status();

        return;
    }
}

/// Emit the monomorphic embassy wrapper for the generic
/// [`storage_task`] — embassy tasks cannot be generic, so every device
/// needs one; this macro is that one.
///
/// `device:` names the `StackDefinition` type, `system:` the
/// [`SystemControl`](zweidraehte_platform::SystemControl) reset value, and
/// `guard:` the [`SaveGuard`] expression raised around the task's long flash
/// work (`NoSaveGuard` on KNX/IP and RF devices, `busy_gate()` on TP1). The
/// wrapper takes only the `Stack` handle — the storage handle rides on the
/// stack itself (`StackDefinition::Storage`):
///
/// ```ignore
/// zweidraehte_device::storage_task! {
///     device: PicoTp1LightSwitch,
///     system: embedded_common::CortexMSystem,
///     guard: busy_gate(),
/// }
/// // in main():
/// spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");
/// ```
#[macro_export]
macro_rules! storage_task {
    (
        device: $device:ty,
        system: $system:expr,
        guard: $guard:expr $(,)?
    ) => {
        /// This device's storage work: restart handling, flush retries and
        /// log compaction — the monomorphic wrapper over the framework's
        /// generic `storage_task` (embassy tasks can't be generic).
        #[embassy_executor::task]
        async fn storage_task(knx: $crate::Stack<'static, $device>) -> ! {
            $crate::storage::storage_task(knx, $system, $guard).await
        }
    };
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use zweidraehte_proto::messages::buffers::BufferManager;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::channel::Channel;
    use zweidraehte_platform::SystemControl;
    use zweidraehte_proto::AccessContext;
    use zweidraehte_proto::address::IndividualAddress;
    use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
    use zweidraehte_proto::messages::knx::{KnxMessageBuffer, ServiceType};

    use crate::bcus::system_b::{SystemBStateInit, Tp1};
    use crate::layers::linklayers::mock::{InjectedFrame, MockLinkLayerBuilder};
    use crate::objects::comm::NoComObjects;
    use crate::restart::{EraseCode, RestartRequest, RestartType};
    use crate::storage::{ConfigFlush, StaticIdentity, StorageHooks};
    use crate::{DeviceDefinition, NoParams, StackDefinition, StackResources, StackState};

    use super::{NoSaveGuard, SaveGuard, SaveGuardToken, restart, storage_task};

    const DEVICE: DeviceDescriptor =
        DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 0x01, 1, 1, 1, 0);

    #[derive(Clone, Copy)]
    struct TestDefinition;

    impl DeviceDefinition for TestDefinition {
        type Buffers = BufferManager<4>;
        const DEVICE: &'static DeviceDescriptor = &DEVICE;

        type Params = NoParams;
        type ComObjects = NoComObjects;
        type LinkLayer = MockLinkLayerBuilder<1>;
        type Storage = &'static ProbeStorage;
    }

    type TestStack = Tp1<TestDefinition>;
    type TestState = <TestStack as StackDefinition>::State;

    /// A write-through store that records what it was asked to do.
    #[derive(Default)]
    struct ProbeStorage {
        erases: Cell<usize>,
        /// Whether the next flushes fail.
        fail: Cell<bool>,
        /// Successful flushes, and the individual address the last one saw.
        flushes: Cell<usize>,
        flushed_address: Cell<Option<IndividualAddress>>,
        /// Whether the probe asks the task for a compaction.
        wants_compaction: Cell<bool>,
        /// Compactions run, and how many of them had the guard raised.
        compactions: Cell<usize>,
        guarded_compactions: Cell<usize>,
        /// Set by [`ProbeGuard`] while its guard is raised.
        guard_raised: Cell<bool>,
    }

    impl ConfigFlush<TestState> for ProbeStorage {
        const ENABLED: bool = true;

        fn flush_config(&self, state: &TestState) -> Result<(), ()> {
            if self.fail.get() {
                return Err(());
            }
            self.flushes.set(self.flushes.get() + 1);
            self.flushed_address.set(Some(state.individual_address()));
            Ok(())
        }

        fn needs_compaction(&self) -> bool {
            self.wants_compaction.get()
        }

        fn compact(&self, _state: &TestState) -> Result<(), ()> {
            self.compactions.set(self.compactions.get() + 1);
            if self.guard_raised.get() {
                self.guarded_compactions.set(self.guarded_compactions.get() + 1);
            }
            self.wants_compaction.set(false);
            Ok(())
        }
    }

    /// A [`SaveGuard`] that records on the probe whether it is raised.
    struct ProbeGuard(&'static ProbeStorage);

    impl SaveGuard for ProbeGuard {
        type Guard = &'static ProbeStorage;
        async fn acquire(&self) -> Self::Guard {
            self.0.guard_raised.set(true);
            self.0
        }
    }

    impl SaveGuardToken for &'static ProbeStorage {
        async fn release(self) {
            self.guard_raised.set(false);
        }
    }

    impl StorageHooks for ProbeStorage {
        fn erase(&self, _code: EraseCode) {
            self.erases.set(self.erases.get() + 1);
        }
    }

    struct NeverRestart;

    impl SystemControl for NeverRestart {
        type Error = ();

        async fn restart(&mut self) -> Result<!, Self::Error> {
            core::future::pending().await
        }
    }

    fn test_stack(storage: &'static ProbeStorage) -> crate::Stack<'static, TestStack> {
        let resources = Box::leak(Box::new(StackResources::<TestStack>::new()));
        let injection = Box::leak(Box::new(Channel::<NoopRawMutex, InjectedFrame, 1>::new()));
        let (link, _) = MockLinkLayerBuilder::new(injection);
        let (stack, _) = crate::new(
            resources,
            link,
            SystemBStateInit::new(StaticIdentity::new([0; 6])),
            (),
            TestStack::memory_map(),
            storage,
        );

        stack
    }

    /// Run the storage task until `done` holds, or fail after a few ticks.
    fn run_task_until(stack: crate::Stack<'static, TestStack>, guard: ProbeGuard, done: impl Fn() -> bool) {
        let finished = async {
            while !done() {
                embassy_time::Timer::after_millis(10).await;
            }
        };
        let task = storage_task(stack, NeverRestart, guard);
        let run = embassy_futures::select::select(task, finished);
        embassy_futures::block_on(embassy_time::with_timeout(super::STORAGE_TICK * 3, run))
            .expect("the tick acts within a few periods");
    }

    #[test]
    fn restart_waits_for_the_router_outbox_before_erasing() {
        const CONFIGURED_ADDRESS: IndividualAddress = IndividualAddress::new(1, 2, 3);
        const FACTORY_ADDRESS: IndividualAddress = IndividualAddress::new(15, 15, 255);

        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);

        // Model a configured device with its restart response still waiting
        // for the router. Factory reset must not touch either state or storage
        // while that frame remains queued.
        stack.set_individual_address(CONFIGURED_ADDRESS);

        let layer_context = stack.inner.layer_context;
        let queued_buffer = layer_context.buffer_manager.try_alloc_with_size(1).expect("test buffer available");
        layer_context.push_outbox(KnxMessageBuffer::new(queued_buffer, ServiceType::L_Data_Req));

        assert!(layer_context.try_send_restart_request(RestartRequest {
            restart: RestartType::MasterReset(EraseCode::FactoryReset),
            channel: 0,
            access_ctx: AccessContext::MIN_ACCESS,
            needs_response: true,
        }));

        let mut task = std::pin::pin!(storage_task(stack, NeverRestart, NoSaveGuard));
        let mut context = Context::from_waker(Waker::noop());

        // The first poll consumes the restart request and stops at the outbox
        // barrier. No reset side effect may have happened yet.
        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(stack.individual_address(), CONFIGURED_ADDRESS, "runtime state erased before the outbox drained");
        assert_eq!(storage.erases.get(), 0, "erase ran while the response was still queued");
        assert_eq!(storage.flushes.get(), 0, "flush ran while the response was still queued");

        // Once the router has taken the response, the next poll may perform
        // the reset and flush its result.
        drop(layer_context.outbox.borrow_mut().take_next());

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(stack.individual_address(), FACTORY_ADDRESS, "factory reset did not reset the runtime address");
        assert_eq!(storage.erases.get(), 1, "erase did not run after the outbox drained");
        assert_eq!(storage.flushed_address.get(), Some(FACTORY_ADDRESS), "post-erase state was not flushed");
    }

    /// A store that asks for compaction gets it from the task's periodic
    /// tick, with the save guard raised around it, and only once.
    #[test]
    fn the_tick_compacts_a_store_that_asks_under_the_guard() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);
        storage.wants_compaction.set(true);

        run_task_until(stack, ProbeGuard(storage), || storage.compactions.get() > 0);

        assert_eq!(storage.compactions.get(), 1);
        assert_eq!(storage.guarded_compactions.get(), 1, "compaction ran without the save guard");
        assert!(!storage.guard_raised.get(), "the guard stays raised after compaction");
    }

    /// A router flush that failed leaves the state dirty; the tick retries
    /// it, and a successful retry clears the flag without erasing the
    /// failure from the status history.
    #[test]
    fn the_tick_retries_a_failed_flush() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);

        stack.state().mark_dirty();
        storage.fail.set(true);
        assert_eq!(stack.flush_config(), Err(()));
        assert!(stack.state().is_dirty());
        assert_eq!(stack.status().persistence.failures, 1);

        storage.fail.set(false);
        run_task_until(stack, ProbeGuard(storage), || storage.flushes.get() > 0);

        assert!(!stack.state().is_dirty(), "a successful retry clears the dirty flag");
        assert_eq!(stack.status().persistence.failures, 1);
    }

    struct CountRestart<'a>(&'a Cell<usize>);

    impl SystemControl for CountRestart<'_> {
        type Error = ();

        async fn restart(&mut self) -> Result<!, Self::Error> {
            self.0.set(self.0.get() + 1);

            Err(())
        }
    }

    #[test]
    fn restart_retries_failed_flushes_without_repeating_erase_or_resetting_early() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);
        let resets = Cell::new(0);
        let mut system = CountRestart(&resets);
        let request = RestartRequest {
            restart: RestartType::MasterReset(EraseCode::FactoryReset),
            channel: 0,
            access_ctx: AccessContext::MIN_ACCESS,
            needs_response: true,
        };

        storage.fail.set(true);

        let mut task = std::pin::pin!(restart(stack, request, &mut system, &NoSaveGuard));
        let mut context = Context::from_waker(Waker::noop());

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(resets.get(), 0);
        assert_eq!(storage.erases.get(), 1);
        assert!(stack.status().persistence.restarting);
        assert!(stack.state().is_dirty());

        storage.fail.set(false);
        std::thread::sleep(std::time::Duration::from_millis(1100));

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(resets.get(), 0);
        assert_eq!(storage.erases.get(), 1);
        assert_eq!(storage.flushes.get(), 1);

        // A write during response settling needs another flush before reset.
        stack.set_individual_address(IndividualAddress::new(1, 2, 9));
        std::thread::sleep(std::time::Duration::from_millis(120));

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(resets.get(), 0);
        assert_eq!(storage.flushes.get(), 2);
        assert_eq!(storage.flushed_address.get(), Some(IndividualAddress::new(1, 2, 9)));

        std::thread::sleep(std::time::Duration::from_millis(120));

        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(()));
        assert_eq!(resets.get(), 1);
        assert_eq!(storage.erases.get(), 1);
    }
}
