//! Device model layer for lifecycle orchestration.
//!
//! The device model handles the side effects of run state machine transitions:
//! DeviceControl synchronization, lifecycle events, and communication object
//! initialization. Different mask versions (System B, System 7, etc.) provide
//! their own implementations.
//!
//! # Architecture
//!
//! The composition layer ([`InsecureDeviceLayers`](crate::composition::InsecureDeviceLayers))
//! detects run state transitions by comparing `is_running()` before and after
//! dispatching messages through the protocol stack. When a transition occurs,
//! it calls [`DeviceModel::on_action`] with the appropriate [`RunAction`].
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │ InsecureDeviceLayers                                    │
//! │                                                         │
//! │  ┌────┐ ┌────┐ ┌────┐   ┌───────────────────────────┐  │
//! │  │ NL │ │ TL │ │ AL │   │ DeviceModel               │  │
//! │  └────┘ └────┘ └────┘   │ (e.g. SystemBDeviceModel)  │  │
//! │                          └───────────────────────────┘  │
//! │                                                         │
//! │  was_running ──► dispatch() ──► is_running              │
//! │                    if changed: DeviceModel::on_action()  │
//! └─────────────────────────────────────────────────────────┘
//! ```

use core::cell::RefCell;

use embassy_sync::pubsub::{PubSubBehavior, PubSubChannel};

use crate::{
    definition::StackDefinition,
    objects::{
        comm::{ComObjects, LifecycleEvent},
        interface::HasDeviceObject,
        tables::{HasApplication, HasRunStateMachine, RunAction},
    },
};

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
    D::State: HasApplication,
    D::InterfaceObjects<'static>: HasDeviceObject,
    D::CO: Sized,
{
    fn init(&mut self) {
        // Initialize the run state machine. If the application is already
        // loaded from persistent storage, this transitions it to RUNNING.
        self.state.app().borrow_mut().init_run_state();

        let is_running = self.state.app().borrow().is_running();
        self.interface_objects.set_user_stopped(!is_running);

        if is_running {
            self.on_action(RunAction::Started);
        }
    }

    fn on_action(&mut self, action: RunAction) {
        match action {
            RunAction::Started => {
                self.interface_objects.set_user_stopped(false);
                self.comm_objs.borrow_mut().reset();
                self.lifecycle_channel
                    .publish_immediate(LifecycleEvent::ApplicationStarted);
            }
            RunAction::Stopped => {
                self.interface_objects.set_user_stopped(true);
                self.lifecycle_channel
                    .publish_immediate(LifecycleEvent::ApplicationStopped);
            }
            RunAction::None => {}
        }
    }
}
