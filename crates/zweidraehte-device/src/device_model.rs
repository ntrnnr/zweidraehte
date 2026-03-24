//! Device model layer for lifecycle orchestration.
//!
//! The device model handles the side effects of run state machine transitions:
//! DeviceControl synchronization, lifecycle events, and communication object
//! initialization. Different mask versions (System B, System 7, etc.) provide
//! their own implementations.
//!
//! # Architecture
//!
//! Interface objects (specifically [`ApplicationProgramObject`](crate::objects::interface::standard::ApplicationProgramObject))
//! post [`DeviceModelEvent`]s to the shared device state via the
//! [`DeviceModelNotifier`] trait. The composition layer drains these each
//! dispatch cycle:
//!
//! ```text
//! write_rsm() / write_lsm()
//!   → ApplicationProgramObject calls state.notify(DeviceModelEvent::RunAction(..))
//!   → Runner drain loop
//!   → InsecureDeviceLayers::drain_events()
//!     → DeviceModel::drain_dm_events() calls state.take_event()
//!     → DeviceModel::on_action()
//! ```

use core::cell::{Cell, RefCell};

use embassy_sync::pubsub::{PubSubBehavior, PubSubChannel};

use crate::{
    definition::StackDefinition,
    objects::{
        comm::{ComObjects, LifecycleEvent},
        interface::HasDeviceObject,
        tables::{HasApplication, HasLoadStateMachine, HasRunStateMachine, RunAction, RunEvent},
    },
};

// ============================================================================
// DeviceModel Events and Notification
// ============================================================================

/// Events sent to the DeviceModel for lifecycle orchestration.
///
/// Posted synchronously by interface objects (e.g.
/// [`ApplicationProgramObject`](crate::objects::interface::standard::ApplicationProgramObject))
/// via [`DeviceModelNotifier::notify`]. Drained by
/// [`DeviceModel::drain_dm_events`] after each dispatch cycle.
#[derive(Debug, Clone, Copy)]
pub enum DeviceModelEvent {
    /// The RSM crossed the running/not-running boundary.
    /// The DeviceModel should handle lifecycle side effects (DeviceControl,
    /// comm object reset, lifecycle events to user code).
    RunAction(RunAction),
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
    /// [`LayerStack::drain_events`](crate::router::LayerStack::drain_events).
    fn drain_dm_events(&mut self);

    /// Handle a lifecycle action produced by a run state transition.
    fn on_action(&mut self, action: RunAction);
}

// ============================================================================
// System B Device Model
// ============================================================================

/// Device model implementation for System B devices.
///
/// Handles lifecycle transitions by:
/// - Synchronizing `DeviceControl.user_stopped` via the interface objects
/// - Resetting communication objects when the application starts (so that
///   read-on-init re-reads values from the bus)
/// - Publishing [`LifecycleEvent`]s for user code
pub struct SystemBDeviceModel<'a, D: StackDefinition> {
    state: &'a D::State,
    comm_objs: &'a RefCell<D::CO>,
    lifecycle_channel: &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
    interface_objects: &'a D::InterfaceObjects<'static>,
}

impl<'a, D: StackDefinition> SystemBDeviceModel<'a, D> {
    pub fn new(
        state: &'a D::State,
        comm_objs: &'a RefCell<D::CO>,
        lifecycle_channel: &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
        interface_objects: &'a D::InterfaceObjects<'static>,
    ) -> Self {
        Self { state, comm_objs, lifecycle_channel, interface_objects }
    }
}

impl<D: StackDefinition> DeviceModel for SystemBDeviceModel<'_, D>
where
    D::State: HasApplication + DeviceModelNotifier,
    D::InterfaceObjects<'static>: HasDeviceObject,
    D::CO: Sized,
{
    fn init(&mut self) {
        // Default to stopped until the RSM says otherwise.
        self.interface_objects.set_user_stopped(true);

        if self.state.app().borrow().is_loaded() {
            // App is loaded from persistent storage. Cascade the startup
            // sequence: Loaded → Ready, then ReadyToRun → Running.
            // (Cascades load-state and run-state startup in one step.)
            self.state.app().borrow_mut().handle_run_event(RunEvent::Loaded);
            let action = self.state.app().borrow_mut().handle_run_event(RunEvent::ReadyToRun);
            if let Some(action) = action {
                self.on_action(action);
            }
        }
    }

    fn drain_dm_events(&mut self) {
        while let Some(event) = self.state.take_event() {
            match event {
                DeviceModelEvent::RunAction(action) => self.on_action(action),
            }
        }
    }

    fn on_action(&mut self, action: RunAction) {
        match action {
            RunAction::Started => {
                self.interface_objects.set_user_stopped(false);
                self.comm_objs.borrow_mut().reset();
                self.lifecycle_channel.publish_immediate(LifecycleEvent::ApplicationStarted);
            }
            RunAction::Stopped => {
                self.interface_objects.set_user_stopped(true);
                self.lifecycle_channel.publish_immediate(LifecycleEvent::ApplicationStopped);
            }
        }
    }
}
