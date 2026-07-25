//! Device model layer for lifecycle orchestration.
//!
//! The device model handles the side effects of run state machine transitions:
//! DeviceControl synchronization, lifecycle events, and communication object
//! initialization. Different mask versions (System B, System 7, etc.) provide
//! their own implementations.
//!
//! # Architecture
//!
//! Interface objects (specifically [`ApplicationProgramObject`](crate::objects::interface::ApplicationProgramObject))
//! post [`DeviceModelEvent`]s to the shared device state via the
//! [`DeviceModelNotifier`] trait. The composition layer drains these each
//! dispatch cycle:
//!
//! ```text
//! write_rsm() / write_lsm()
//!   → ApplicationProgramObject calls state.notify(DeviceModelEvent::RunAction(..))
//!   → Runner drain loop
//!   → LayerRegistry::drain_events() (derive-generated)
//!     → DeviceModel::drain_dm_events() calls state.take_event()
//!     → DeviceModel::on_action()
//! ```

use core::cell::Cell;

use crate::objects::tables::RunAction;

// ============================================================================
// DeviceModel Events and Notification
// ============================================================================

/// Which program's run state machine produced a [`RunAction`].
///
/// Needed because both the Application Program Object and the PEI Program
/// Object can transition independently, and the DeviceModel's side effects
/// (comm object reset, `user_stopped` flag, lifecycle event published to
/// user code) are tied to the Application program only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunTarget {
    /// Application Program Object (IOT 0x0003).
    Application,
    /// PEI Program Object (IOT 0x0005).
    Pei,
}

/// Events sent to the DeviceModel for lifecycle orchestration.
///
/// Posted synchronously by interface objects (e.g.
/// [`ApplicationProgramObject`](crate::objects::interface::ApplicationProgramObject))
/// via [`DeviceModelNotifier::notify`]. Drained by
/// [`DeviceModel::drain_dm_events`] after each dispatch cycle.
#[derive(Debug, Clone, Copy)]
/// `#[non_exhaustive]`: every construction/match site is inside this crate,
/// where the attribute has no effect — so in-crate exhaustiveness checking
/// is preserved while downstream crates stay insulated from new variants.
#[non_exhaustive]
pub enum DeviceModelEvent {
    /// An RSM crossed the running/not-running boundary. The DeviceModel
    /// should handle lifecycle side effects (DeviceControl, comm object
    /// reset, lifecycle events to user code) — scoped by [`RunTarget`]
    /// since only the Application program drives DeviceControl / comm
    /// object state.
    RunAction(RunTarget, RunAction),
}

/// Trait for buffering [`DeviceModelEvent`]s on the device state.
///
/// Implemented on `D::State` so that both interface objects and the
/// [`DeviceModel`] can access the notification slot through the shared
/// state reference they already hold. This avoids threading channels or
/// sender handles through constructors.
pub trait DeviceModelNotifier {
    /// Post an event for the DeviceModel to process.
    ///
    /// Called synchronously during property writes. The current
    /// implementation uses a single-slot `Cell`, so only the last event
    /// per dispatch cycle is retained. In practice at most one event
    /// fires per cycle (one property write → one state machine transition).
    fn notify(&self, event: DeviceModelEvent);

    /// Take the pending event, if any.
    ///
    /// Called by [`DeviceModel::drain_dm_events`] after each dispatch cycle.
    fn take_event(&self) -> Option<DeviceModelEvent>;
}

/// Embeddable single-slot notification buffer for [`DeviceModelEvent`]s.
///
/// Device state types should embed this and delegate their
/// [`DeviceModelNotifier`] implementation to it.
///
/// # Example
///
/// ```rust,ignore
/// struct MyState {
///     dm_slot: DmNotificationSlot,
///     // ...other fields...
/// }
///
/// impl DeviceModelNotifier for MyState {
///     fn notify(&self, event: DeviceModelEvent) { self.dm_slot.notify(event); }
///     fn take_event(&self) -> Option<DeviceModelEvent> { self.dm_slot.take_event(); }
/// }
/// ```
pub struct DmNotificationSlot(Cell<Option<DeviceModelEvent>>);

impl Default for DmNotificationSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl DmNotificationSlot {
    /// Create an empty notification slot.
    pub const fn new() -> Self {
        Self(Cell::new(None))
    }
}

impl DeviceModelNotifier for DmNotificationSlot {
    fn notify(&self, event: DeviceModelEvent) {
        self.0.set(Some(event));
    }

    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.0.take()
    }
}

// ============================================================================
// DeviceModel trait
// ============================================================================

/// Device-model-specific lifecycle orchestration.
///
/// Implementations handle the side effects of application run state transitions
/// (started/stopped). The composition layer calls [`on_action`](Self::on_action)
/// whenever the run state changes, and [`init`](Self::init) once at startup.
pub trait DeviceModel {
    /// Initialize the device model at startup.
    ///
    /// Called once from the composition layer's `init()`, before the router
    /// loop starts. Implementations should initialize the run state machine
    /// and handle any resulting transition (e.g., auto-starting a pre-loaded
    /// application from persistent storage).
    fn init(&mut self);

    /// Drain and handle [`DeviceModelEvent`]s from the DM channel.
    ///
    /// Called by the composition layer after each dispatch cycle via
    /// [`LayerRegistry::drain_events`](crate::service::LayerRegistry::drain_events).
    fn drain_dm_events(&mut self);

    /// Handle a lifecycle action produced by a run state transition.
    ///
    /// This is the dispatch primitive that [`init`](Self::init) and
    /// [`drain_dm_events`](Self::drain_dm_events) feed — not an external
    /// entry point. The composition layer drives the device model
    /// exclusively through those two methods; call this directly only
    /// when implementing a `DeviceModel` yourself.
    fn on_action(&mut self, action: RunAction);
}
