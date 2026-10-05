//! The generic storage task: one body, every device.
//!
//! The router persists every configuration change itself, before the
//! response to it leaves the device ([`DeviceStorage`], write-through). What
//! remains for a task is the work that must not run inside a dispatch:
//!
//! - **Restart requests** (the application layer's A_Restart handler on
//!   `restart_channel`): apply the erase code, flush what it changed, reset
//!   the device.
//! - **Maintenance**: compact a log store that asks for it
//!   ([`DeviceStorage::needs_compaction`]) behind the [`SaveGuard`]. Every
//!   flush that leaves the store asking wakes the task, so no erase runs in
//!   the router's dispatch path. Nothing retries a failed medium on a
//!   timer: a failure is logged and counted, the state stays dirty, and the
//!   next flush tries again.
//!
//! The IP Secure mc_timer watermark is **not** handled here: its durability
//! ordering is synchronous, so the KNX/IP Secure link layer writes it into
//! the independent watermark store directly through the storage handle.
//!
//! Devices spawn it through the `storage_task!` macro (which emits the
//! monomorphic embassy wrapper — embassy tasks can't be generic).

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};

use zweidraehte_platform::SystemControl;

use crate::definition::StackDefinition;
use crate::restart::RestartType;
use crate::stack_handle::Stack;
use crate::state::HasPersistence;
use crate::timing::time_divisor;

use super::{DeviceStorage, FlushError};

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
/// [`NoSaveGuard`], which just runs the work.
///
/// Raising and lowering are both async (arming the chip is a
/// request/response rendezvous), and there is no async `Drop` to lower a
/// guard that goes out of scope. Taking the work as a closure makes the
/// guard lower itself on the one path out, so no caller can forget to.
// `async fn` (not `-> impl Future + Send`): the storage task runs on a
// single-threaded embassy executor, so no `Send` bound is wanted — the lint's
// suggested workaround would impose one we'd then have to fight.
#[allow(async_fn_in_trait)]
pub trait SaveGuard {
    /// Raise the guard, run `work` (which may stall the executor), lower
    /// the guard, and return what `work` returned.
    async fn guarded<R>(&self, work: impl FnOnce() -> R) -> R;
}

/// The no-op [`SaveGuard`] for devices whose saves don't stall the link layer
/// (KNX/IP, RF).
pub struct NoSaveGuard;

impl SaveGuard for NoSaveGuard {
    async fn guarded<R>(&self, work: impl FnOnce() -> R) -> R {
        work()
    }
}

// ============================================================================
// RestartHook — announce a restart to whoever observes the device
// ============================================================================

/// Told about an impending restart, at the top of the storage task's restart
/// arm: after the outbox has drained and before any erase touches state.
///
/// A device that simply resets has nothing to announce and passes
/// [`NoRestartHook`]. The hook exists for devices whose restart is observed
/// by an external party that has to be told while the outgoing frames are
/// still in flight, rather than after the device has stopped serving the
/// bus. The conformance DUTs are the case in point: their harness couples
/// the "I am exiting" notification onto the in-flight step reply, so
/// announcing any later than here is indistinguishable from the DUT dying
/// unannounced.
///
/// It belongs to whoever owns the reset line, not to the stores, which is why
/// it is a storage-task parameter beside [`SystemControl`] rather than a
/// storage method. It is a trait of its own rather than a method on
/// `SystemControl` so the platform crate need not know about restart types.
///
/// The hook is `Copy` and handed to each restart by value. Holding a
/// reference to it instead would put a pointer into the storage task's
/// future for every device, even those whose hook is the zero-sized
/// [`NoRestartHook`].
#[allow(async_fn_in_trait)]
pub trait RestartHook: Copy {
    /// Announce `restart`, which the storage task is about to apply. Called
    /// before the erase, so the announcement sees pre-erase state.
    async fn prepare_restart(self, restart: RestartType);
}

/// The no-op [`RestartHook`] for every device that just resets.
#[derive(Clone, Copy)]
pub struct NoRestartHook;

impl RestartHook for NoRestartHook {
    async fn prepare_restart(self, _restart: RestartType) {}
}

// ============================================================================
// storage_task
// ============================================================================

/// Drive a device's storage work: restart requests and maintenance.
///
/// - A [`RestartRequest`](crate::restart::RestartRequest) first lets the
///   router outbox drain (the application layer queues the A_Restart_Response
///   *before* the request, and the network layer stamps its source address
///   only on the way out — erasing earlier sends the response from the
///   default individual address), announces the restart
///   ([`RestartHook::prepare_restart`] — a no-op unless something outside
///   the device is watching), then applies the erase code to the runtime
///   state ([`HasPersistence::apply_erase_code`], master resets only) and the durable regions
///   ([`DeviceStorage::erase`] — mc_timer clear + sending-SeqNr exhaustion
///   re-init on factory codes), waits [`RESTART_SETTLE_DELAY`], flushes the
///   result, and resets via [`SystemControl`].
/// - Maintenance, when a flush leaves the store asking for it, compacts the
///   store under the guard. It compiles away for a storage handle without
///   write-through ([`DeviceStorage::WRITE_THROUGH`] false).
pub async fn storage_task<D, S, G, H>(knx: Stack<'static, D>, mut system: S, guard: G, hook: H) -> !
where
    D: StackDefinition,
    D::Storage: DeviceStorage<D::State>,
    S: SystemControl,
    G: SaveGuard,
    H: RestartHook,
{
    loop {
        match select(knx.receive_restart_request(), knx.wait_maintenance()).await {
            Either::First(request) => {
                restart(knx, request, &mut system, &guard, hook).await;
            }
            Either::Second(()) => {
                if <D::Storage as DeviceStorage<D::State>>::WRITE_THROUGH {
                    compact_if_needed(knx, &guard).await;
                    knx.publish_status();
                }
            }
        }
    }
}

/// Compact a write-through store that asks for it, under the [`SaveGuard`].
///
/// A deferred append leaves the state dirty. Compaction snapshots that
/// state, making the pending change durable without re-appending it.
/// Stores without history never ask. A failed compaction is logged; the
/// store keeps asking, so the next flush wakes the task to try again.
async fn compact_if_needed<D, G>(knx: Stack<'static, D>, guard: &G)
where
    D: StackDefinition,
    D::Storage: DeviceStorage<D::State>,
    G: SaveGuard,
{
    if !knx.storage().needs_compaction() {
        return;
    }

    guard.guarded(|| compact(knx)).await;
}

/// Compact the store now; the caller holds the [`SaveGuard`].
fn compact<D>(knx: Stack<'static, D>)
where
    D: StackDefinition,
    D::Storage: DeviceStorage<D::State>,
{
    if knx.storage().compact(knx.state()).is_ok() {
        // Clear while the guarded snapshot still owns this executor turn.
        // Another task may mark the state dirty as the guard lowers.
        knx.state().clear_dirty();
    } else {
        crate::logging::warn!("config compaction failed; the next flush retries");
    }
}

/// Apply an accepted restart, make its changes durable, and reset.
///
/// Drain before erasing so the response retains the old source address. The
/// flush runs once, after the settle delay, so it also covers anything the
/// router changed meanwhile. A medium that fails it is logged and the device
/// resets anyway: retrying a broken medium would only keep the device from
/// restarting. A failed platform reset returns to the caller after clearing
/// restart status.
pub async fn restart<D, S, G, H>(
    knx: Stack<'static, D>,
    request: crate::restart::RestartRequest,
    system: &mut S,
    guard: &G,
    hook: H,
) where
    D: StackDefinition,
    D::Storage: DeviceStorage<D::State>,
    S: SystemControl,
    G: SaveGuard,
    H: RestartHook,
{
    let context = knx.inner.layer_context;
    let storage = knx.storage();

    context.restarting.set(true);
    knx.publish_status();

    let _ = select(knx.await_outbox_drained(), Timer::after(OUTBOX_DRAIN_TIMEOUT)).await;

    hook.prepare_restart(request.restart).await;
    // A basic restart erases nothing; only a master reset has an erase code.
    if let RestartType::MasterReset(erase_code) = request.restart {
        knx.state().apply_erase_code(erase_code);
        storage.erase(erase_code);
    }
    knx.publish_status();

    Timer::after(restart_settle_delay()).await;

    // The flush compares every Record with its durable copy, so it also
    // catches state that ordinary dirty tracking leaves out, such as the
    // security failure counters. An erase touches many sections: keep the
    // bus guarded throughout, and complete a deferred flush with the
    // compaction right here.
    guard
        .guarded(|| {
            if knx.flush_config() == Err(FlushError::Deferred) {
                compact(knx);
            }
        })
        .await;
    knx.publish_status();

    let _ = system.restart().await;

    context.restarting.set(false);
    knx.publish_status();
}

/// Emit the monomorphic embassy wrapper for the generic
/// [`storage_task`] — embassy tasks cannot be generic, so every device
/// needs one; this macro is that one.
///
/// `device:` names the `StackDefinition` type, `system:` the
/// [`SystemControl`](zweidraehte_platform::SystemControl) reset value,
/// `guard:` the [`SaveGuard`] expression raised around the task's long flash
/// work (`NoSaveGuard` on KNX/IP and RF devices, `busy_gate()` on TP1), and
/// the optional `restart_hook:` the [`RestartHook`] told about a restart
/// before it is applied ([`NoRestartHook`] when omitted). The
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
        $crate::storage_task! {
            device: $device,
            system: $system,
            guard: $guard,
            restart_hook: $crate::storage::NoRestartHook,
        }
    };
    (
        device: $device:ty,
        system: $system:expr,
        guard: $guard:expr,
        restart_hook: $hook:expr $(,)?
    ) => {
        /// This device's storage work: restart handling, flush retries and
        /// log compaction — the monomorphic wrapper over the framework's
        /// generic `storage_task` (embassy tasks can't be generic).
        #[embassy_executor::task]
        async fn storage_task(knx: $crate::Stack<'static, $device>) -> ! {
            $crate::storage::storage_task(knx, $system, $guard, $hook).await
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
    use crate::storage::{DeviceStorage, FlushError, StaticIdentity};
    use crate::{DeviceDefinition, NoParams, StackDefinition, StackResources, StackState};

    use super::{NoRestartHook, NoSaveGuard, SaveGuard, restart, storage_task};

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
        type Storage = ProbeStorage;
    }

    type TestStack = Tp1<TestDefinition>;
    type TestState = <TestStack as StackDefinition>::State;

    /// A write-through store that records what it was asked to do.
    #[derive(Default)]
    struct ProbeStorage {
        erases: Cell<usize>,
        /// How the next flushes fail, if they do.
        fail: Cell<Option<FlushError>>,
        /// Whether compactions fail.
        compaction_fails: Cell<bool>,
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

    impl DeviceStorage<TestState> for ProbeStorage {
        const WRITE_THROUGH: bool = true;

        fn flush(&self, state: &TestState) -> Result<(), FlushError> {
            if let Some(error) = self.fail.get() {
                return Err(error);
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
            if self.compaction_fails.get() {
                return Err(());
            }

            // The snapshot completes a deferred write, as a full log's does.
            self.wants_compaction.set(false);
            if self.fail.get() == Some(FlushError::Deferred) {
                self.fail.set(None);
            }
            Ok(())
        }

        fn erase(&self, _code: EraseCode) {
            self.erases.set(self.erases.get() + 1);
        }
    }

    /// A [`SaveGuard`] that records on the probe whether it is raised.
    struct ProbeGuard(&'static ProbeStorage);

    impl SaveGuard for ProbeGuard {
        async fn guarded<R>(&self, work: impl FnOnce() -> R) -> R {
            self.0.guard_raised.set(true);
            let result = work();
            self.0.guard_raised.set(false);
            result
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
        )
        .expect("the test storage loads");

        stack
    }

    /// Run the storage task for `duration`, whatever it does.
    fn run_task_for(stack: crate::Stack<'static, TestStack>, guard: ProbeGuard, duration: embassy_time::Duration) {
        let task = storage_task(stack, NeverRestart, guard, NoRestartHook);
        embassy_futures::block_on(embassy_futures::select::select(task, embassy_time::Timer::after(duration)));
    }

    /// Long enough for the task to act on a wake, far shorter than any
    /// periodic retry would be.
    const SETTLE: embassy_time::Duration = embassy_time::Duration::from_millis(50);

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

        let mut task = std::pin::pin!(storage_task(stack, NeverRestart, NoSaveGuard, NoRestartHook));
        let mut context = Context::from_waker(Waker::noop());

        // The first poll consumes the restart request and stops at the outbox
        // barrier. No reset side effect may have happened yet.
        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(stack.individual_address(), CONFIGURED_ADDRESS, "runtime state erased before the outbox drained");
        assert_eq!(storage.erases.get(), 0, "erase ran while the response was still queued");
        assert_eq!(storage.flushes.get(), 0, "flush ran while the response was still queued");

        // Once the router has taken the response, the next poll may perform
        // the reset, and the poll after the settle delay flushes its result.
        drop(layer_context.outbox.borrow_mut().take_next());

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(stack.individual_address(), FACTORY_ADDRESS, "factory reset did not reset the runtime address");
        assert_eq!(storage.erases.get(), 1, "erase did not run after the outbox drained");

        std::thread::sleep(std::time::Duration::from_millis(120));

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(storage.flushed_address.get(), Some(FACTORY_ADDRESS), "post-erase state was not flushed");
    }

    /// A deferred flush is no failure. It wakes the task, which compacts
    /// once, under the guard, completing the write.
    #[test]
    fn a_deferred_flush_wakes_the_task_to_compact_under_the_guard() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);

        stack.state().mark_dirty();
        storage.fail.set(Some(FlushError::Deferred));
        storage.wants_compaction.set(true);
        assert_eq!(stack.flush_config(), Err(FlushError::Deferred));
        assert_eq!(stack.status().persistence.failures, 0, "a deferral counted as a failure");

        run_task_for(stack, ProbeGuard(storage), SETTLE);

        assert_eq!(storage.compactions.get(), 1);
        assert_eq!(storage.guarded_compactions.get(), 1, "compaction ran without the save guard");
        assert!(!storage.guard_raised.get(), "the guard stays raised after compaction");
        assert!(!stack.state().is_dirty(), "the snapshot did not settle the deferred change");
    }

    /// A successful flush that leaves the log past its threshold wakes the
    /// task too, so compaction happens before the bank fills.
    #[test]
    fn a_flush_past_the_threshold_wakes_the_task() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);

        stack.state().mark_dirty();
        storage.wants_compaction.set(true);
        assert_eq!(stack.flush_config(), Ok(()));

        run_task_for(stack, ProbeGuard(storage), SETTLE);

        assert_eq!(storage.compactions.get(), 1);
        assert_eq!(storage.guarded_compactions.get(), 1, "compaction ran without the save guard");
    }

    /// Without a flush asking, the task does nothing: no periodic retry of
    /// a failed flush, and a failed compaction is not repeated until the
    /// next flush wakes the task again.
    #[test]
    fn the_task_only_acts_when_a_flush_wakes_it() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);

        stack.state().mark_dirty();
        storage.fail.set(Some(FlushError::Deferred));
        storage.wants_compaction.set(true);
        storage.compaction_fails.set(true);
        assert_eq!(stack.flush_config(), Err(FlushError::Deferred));

        run_task_for(stack, ProbeGuard(storage), SETTLE * 4);

        assert_eq!(storage.compactions.get(), 1, "a failed compaction was retried without a new flush");
        assert!(stack.state().is_dirty());
    }

    struct CountRestart<'a>(&'a Cell<usize>);

    impl SystemControl for CountRestart<'_> {
        type Error = ();

        async fn restart(&mut self) -> Result<!, Self::Error> {
            self.0.set(self.0.get() + 1);

            Err(())
        }
    }

    fn factory_reset() -> RestartRequest {
        RestartRequest {
            restart: RestartType::MasterReset(EraseCode::FactoryReset),
            channel: 0,
            access_ctx: AccessContext::MIN_ACCESS,
            needs_response: true,
        }
    }

    /// The restart flushes once, after the settle delay, so a change made
    /// while the response settles is part of it; then it resets.
    #[test]
    fn restart_flushes_once_after_settling_then_resets() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);
        let resets = Cell::new(0);
        let mut system = CountRestart(&resets);

        let mut task = std::pin::pin!(restart(stack, factory_reset(), &mut system, &NoSaveGuard, NoRestartHook));
        let mut context = Context::from_waker(Waker::noop());

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(storage.erases.get(), 1);
        assert_eq!(storage.flushes.get(), 0, "flushed before the response settled");
        assert!(stack.status().persistence.restarting);

        // A write while the response settles.
        stack.set_individual_address(IndividualAddress::new(1, 2, 9));
        std::thread::sleep(std::time::Duration::from_millis(120));

        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(()));
        assert_eq!(storage.flushes.get(), 1);
        assert_eq!(storage.flushed_address.get(), Some(IndividualAddress::new(1, 2, 9)));
        assert_eq!(resets.get(), 1);
        assert_eq!(storage.erases.get(), 1);
    }

    /// A medium that fails the restart's flush is logged and counted; the
    /// device resets anyway rather than retrying a broken medium.
    #[test]
    fn restart_resets_even_if_the_flush_fails() {
        let storage = Box::leak(Box::new(ProbeStorage::default()));
        let stack = test_stack(storage);
        let resets = Cell::new(0);
        let mut system = CountRestart(&resets);

        storage.fail.set(Some(FlushError::Failed));

        let mut task = std::pin::pin!(restart(stack, factory_reset(), &mut system, &NoSaveGuard, NoRestartHook));
        let mut context = Context::from_waker(Waker::noop());

        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
        std::thread::sleep(std::time::Duration::from_millis(120));

        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(()));
        assert_eq!(resets.get(), 1);
        assert_eq!(stack.status().persistence.failures, 1);
    }
}
