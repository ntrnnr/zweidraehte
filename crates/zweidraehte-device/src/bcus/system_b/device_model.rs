//! System B device model.
//!
//! [`SystemBDeviceModel`] implements the generic
//! [`DeviceModel`](crate::device_model::DeviceModel) trait, handling the side
//! effects of application run-state transitions for System B devices. The
//! generic device-model vocabulary (events, notifier, trait) lives in
//! [`crate::device_model`].

use embassy_sync::pubsub::{PubSubBehavior, PubSubChannel};

use crate::context::LayerContext;
use crate::definition::StackDefinition;
use crate::device_model::{DeviceModel, DeviceModelEvent, DeviceModelNotifier, RunTarget};
use crate::lifecycle::LifecycleEvent;
use crate::objects::{
    comm::{ComObjects, HasCommObjects},
    interface::HasDeviceObject,
    tables::{HasApplication, HasLoadStateMachine, HasRunStateMachine, RunAction, RunEvent},
};
use crate::service::LifecycleHook;

/// Device model implementation for System B devices.
///
/// Handles lifecycle transitions by:
/// - Synchronizing `DeviceControl.user_stopped` via the interface objects
/// - Resetting communication objects when the application starts (so that
///   read-on-init re-reads values from the bus)
/// - Publishing [`LifecycleEvent`]s for user code
pub struct SystemBDeviceModel<'a, D: StackDefinition> {
    state: &'a D::State,
    layer_context: &'a LayerContext<D>,
    interface_objects: &'a D::InterfaceObjects<'static>,
}

impl<'a, D: StackDefinition> SystemBDeviceModel<'a, D> {
    pub fn new(
        state: &'a D::State,
        layer_context: &'a LayerContext<D>,
        interface_objects: &'a D::InterfaceObjects<'static>,
    ) -> Self {
        Self { state, layer_context, interface_objects }
    }

    fn lifecycle_channel(&self) -> &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 4, 1> {
        &self.layer_context.lifecycle_channel
    }
}

impl<D: StackDefinition> DeviceModel for SystemBDeviceModel<'_, D> {
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
                DeviceModelEvent::RunAction(target, action) => self.on_action_for(target, action),
            }
        }
    }

    fn on_action(&mut self, action: RunAction) {
        // Retained for trait compatibility — this entry point always refers to
        // the Application program, since callers without a target discriminator
        // (e.g., the startup cascade in `init`) only drive the application RSM.
        self.on_action_for(RunTarget::Application, action);
    }
}

/// `LifecycleHook` adapter that lets `#[service(lifecycle)]` fields on
/// derived `LayerRegistry` impls drive the device model. The macro
/// emits `LifecycleHook::init(&mut self.device_model)` and
/// `LifecycleHook::drain_events(...)`; both forward to the existing
/// inherent `DeviceModel` methods.
impl<D: StackDefinition> LifecycleHook<D> for SystemBDeviceModel<'_, D> {
    fn init(&mut self) {
        <Self as DeviceModel>::init(self);
    }

    fn drain_events(&mut self) {
        <Self as DeviceModel>::drain_dm_events(self);
    }
}

impl<D: StackDefinition> SystemBDeviceModel<'_, D> {
    fn on_action_for(&mut self, target: RunTarget, action: RunAction) {
        match (target, action) {
            (RunTarget::Application, RunAction::Started) => {
                self.interface_objects.set_user_stopped(false);
                self.state.comm_objects().borrow_mut().reset();
                self.lifecycle_channel().publish_immediate(LifecycleEvent::ApplicationStarted);
                // The application (re)starting is how an ETS download
                // ends — a natural moment to save the freshly written
                // configuration without waiting for the trailing
                // restart. Also fires on the boot cascade, where the
                // state was just loaded and the dirty check in user
                // code's storage task turns it into a no-op.
                self.layer_context.try_send_persist_request(crate::persist::PersistRequest::EtsDownloadComplete);
            }
            (RunTarget::Application, RunAction::Stopped) => {
                self.interface_objects.set_user_stopped(true);
                self.lifecycle_channel().publish_immediate(LifecycleEvent::ApplicationStopped);
            }
            // PEI has no `user_stopped` flag and no associated comm objects —
            // only the lifecycle event is surfaced.
            (RunTarget::Pei, RunAction::Started) => {
                self.lifecycle_channel().publish_immediate(LifecycleEvent::PeiStarted);
            }
            (RunTarget::Pei, RunAction::Stopped) => {
                self.lifecycle_channel().publish_immediate(LifecycleEvent::PeiStopped);
            }
        }
    }
}
