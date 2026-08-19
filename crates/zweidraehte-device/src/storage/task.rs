//! The generic storage task: one body, every device.
//!
//! Replaces the hand-written `persist_task` / `restart_task` each device used
//! to carry in its `main` (and the unguarded periodic saves some main loops
//! grew). One task, generic over the device's [`StackDefinition`], drives all
//! persistence through [`HasConfigStore`] and the composed [`StorageHooks`]:
//! the same body serves a plain config-only device and a full secure device —
//! the absent-store branches compile away via the hooks' no-op defaults.
//!
//! The task multiplexes three sources:
//!
//! - **Restart requests** (the application layer's A_Restart handler on
//!   `restart_channel`): apply the erase code, persist, reset the device.
//! - **Persist notifications** (`persist_channel`): the advisory
//!   ETS-download-complete save.
//! - **A periodic dirty poll** ([`DIRTY_SAVE_POLL`]): saves the config when
//!   [`HasPersistence`] reports unsaved changes — behind the same
//!   [`SaveGuard`] as every other save, so a TP1 device's bus stays answered
//!   during the flash stall (main-loop polling could never guarantee that).
//!
//! The IP Secure mc_timer watermark is **not** handled here: its durability
//! ordering is synchronous, so the KNX/IP Secure link layer writes its store
//! directly through the storage handle on its context.
//!
//! Devices spawn it through the `storage_task!` macro (which emits the
//! monomorphic embassy wrapper — embassy tasks can't be generic).

use embassy_futures::select::{Either3, select, select3};
use embassy_time::{Duration, Ticker, Timer};

use zweidraehte_platform::SystemControl;

use crate::definition::StackDefinition;
use crate::persist::PersistRequest;
use crate::stack_handle::Stack;
use crate::state::HasPersistence;

use super::{HasConfigStore, StorageHooks};

/// How often the task polls [`HasPersistence::is_dirty`] for a pending
/// config save. Cheap (a `Cell` read); one second keeps worst-case data loss
/// after an unsignalled state change to a bounded, human-scale window.
pub const DIRTY_SAVE_POLL: Duration = Duration::from_secs(1);

/// Pause between applying a restart and pulling the reset line.
///
/// Empirical, not spec-derived: long enough for the already-queued
/// A_Restart_Response to leave the link layer (and, on TP1, for the remote
/// TL's retry window to see it) before the device disappears from the bus.
///
/// This is the wall-clock value; conformance builds compress it — see
/// [`restart_settle_delay`].
pub const RESTART_SETTLE_DELAY: Duration = Duration::from_millis(100);

/// The conformance fast-mode divisor — the same `KNX_TIME_DIVISOR` contract
/// as the transport-layer timers. 1 (spec-compliant wall clock) outside
/// conformance builds.
fn time_divisor() -> u64 {
    #[cfg(feature = "conformance")]
    {
        extern crate std;
        std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1)
    }
    #[cfg(not(feature = "conformance"))]
    {
        1
    }
}

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

/// A protection raised around the (executor-stalling) flash write inside the
/// storage task.
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
/// around the synchronous `save_config` call. `release` is explicit (there is
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

/// Drive all of a device's persistence: restart requests, on-demand persist
/// requests, and the periodic dirty-save poll.
///
/// - A [`RestartRequest`](crate::restart::RestartRequest) first lets the
///   router outbox drain (the application layer queues the A_Restart_Response
///   *before* the request, and the network layer stamps its source address
///   only on the way out — erasing earlier sends the response from the
///   default individual address), announces the restart
///   ([`StorageHooks::on_restart`] — a no-op unless something outside the
///   device is watching), then applies the erase code to the runtime
///   state ([`HasPersistence::apply_erase_code`]) and the durable regions
///   ([`StorageHooks::erase`] — mc_timer clear + sending-SeqNr exhaustion
///   re-init on factory codes), persists unconditionally, waits
///   [`RESTART_SETTLE_DELAY`], and resets via [`SystemControl`].
/// - [`PersistRequest::EtsDownloadComplete`] (advisory) saves the config if
///   dirty.
/// - The dirty poll saves the config at most once per [`DIRTY_SAVE_POLL`]
///   when the state reports unsaved changes, replacing the unguarded ad-hoc
///   saves device main loops used to carry.
///
/// Every save is wrapped in the [`SaveGuard`].
pub async fn storage_task<D, S, G>(knx: Stack<'static, D>, mut system: S, guard: G) -> !
where
    D: StackDefinition,
    D::Storage: HasConfigStore<State = D::State> + StorageHooks,
    S: SystemControl,
    G: SaveGuard,
{
    // The handle travels on the stack (`LayerContext`), so the task takes it
    // from there — one flow for every storage consumer.
    let storage = knx.storage();
    let mut tick = Ticker::every(DIRTY_SAVE_POLL);
    loop {
        match select3(knx.receive_restart_request(), knx.receive_persist_request(), tick.next()).await {
            Either3::First(request) => {
                let code = request.erase_code;

                // The A_Restart_Response is still in the router outbox here,
                // and the network layer stamps its source address on the way
                // out — erase first and a FactoryReset answer leaves as
                // 15.15.255, which the remote TL discards as a stranger's
                // frame. Wait for the outbox, capped so a wedged router
                // cannot make the device unrestartable.
                let _ = select(knx.await_outbox_drained(), Timer::after(OUTBOX_DRAIN_TIMEOUT)).await;

                // Announce the restart while the response frames are still in
                // flight — a no-op for a device that just resets, but the only
                // moment that works for one whose restart is watched from
                // outside (see `StorageHooks::on_restart`). Deliberately before
                // the erase, so the announcement reports pre-erase state.
                storage.on_restart(code).await;

                // State-side erase, then durable-storage-side erase.
                knx.state().apply_erase_code(code);
                storage.erase(code);

                // Persist the (possibly reset) state — unconditionally, not
                // just if dirty. A BCU writes management state straight to
                // EEPROM, so on a real BCU *everything* survives a restart;
                // our lazy dirty-flag model must flush here to match. The
                // dirty flag also deliberately under-reports: state that
                // changes on attacker-controlled receive traffic (the
                // security failures log, 03/05/01 §6.3 — "saved at power
                // down and restored at power up", checked across restarts
                // by TSSJ 3.8.12.1/.2) never marks dirty, because doing so
                // would turn a sustained secure-telegram attack into a
                // flash write per DIRTY_SAVE_POLL. A controlled restart is
                // rare and is such state's one durable checkpoint. Behind
                // the busy gate (the bus keeps running while we save — the
                // remote TL may still retry the A_Restart_Response).
                save_config_guarded(knx, storage, &guard).await;

                // `restart` does not return on success. If a platform's
                // implementation ever does return (a mock refusing resets),
                // fall through and keep serving — the *next* restart request
                // would try again; there is no retry of this one.
                Timer::after(restart_settle_delay()).await;
                let _ = system.restart().await;
            }
            Either3::Second(request) => match request {
                PersistRequest::EtsDownloadComplete => {
                    save_if_dirty(knx, storage, &guard).await;
                }
            },
            Either3::Third(()) => {
                save_if_dirty(knx, storage, &guard).await;
            }
        }
    }
}

/// One guarded save, shared by the periodic and on-demand arms of the
/// [`storage_task`] loop: skip when the state is clean; otherwise raise the
/// [`SaveGuard`], write the config blob, and clear the dirty flag before
/// releasing.
async fn save_if_dirty<D, G>(knx: Stack<'static, D>, storage: D::Storage, guard: &G)
where
    D: StackDefinition,
    D::Storage: HasConfigStore<State = D::State>,
    G: SaveGuard,
{
    if knx.state().is_dirty() {
        save_config_guarded(knx, storage, guard).await;
    }
}

/// The guarded save itself, dirty or not. The restart arm calls this
/// directly: some state intentionally never marks dirty (see the restart
/// arm's comment) and a controlled restart is where it gets persisted.
async fn save_config_guarded<D, G>(knx: Stack<'static, D>, storage: D::Storage, guard: &G)
where
    D: StackDefinition,
    D::Storage: HasConfigStore<State = D::State>,
    G: SaveGuard,
{
    let token = guard.acquire().await;
    storage.save_config(knx.state());
    knx.state().clear_dirty();
    token.release().await;
}

/// Emit the monomorphic embassy wrapper for the generic
/// [`storage_task`] — embassy tasks cannot be generic, so every device
/// needs one; this macro is that one.
///
/// `device:` names the `StackDefinition` type, `system:` the
/// [`SystemControl`](zweidraehte_platform::SystemControl) reset value, and
/// `guard:` the [`SaveGuard`] expression raised around each flash save
/// (`NoSaveGuard` on KNX/IP and RF devices, `busy_gate()` on TP1). The
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
        /// All of this device's persistence: restart handling, on-demand
        /// persist requests, and the periodic dirty-save poll — the
        /// monomorphic wrapper over the framework's generic
        /// `storage_task` (embassy tasks can't be generic).
        #[embassy_executor::task]
        async fn storage_task(knx: $crate::Stack<'static, $device>) -> ! {
            $crate::storage::storage_task(knx, $system, $guard).await
        }
    };
}
