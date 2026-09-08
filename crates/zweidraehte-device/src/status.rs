//! Application readiness and configuration durability, independent of the
//! protocol's individual load and run state machines.

use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
    HasRunStateMachine, LoadState, RunState,
};

/// Aggregate facts about the resources required by a selected device profile.
///
/// Loading and failure can coexist on different resources. Keeping both facts
/// avoids hiding an error behind another table that is still loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStatus {
    pub all_loaded: bool,
    pub loading: bool,
    pub error: bool,
}

impl LoadStatus {
    /// Aggregate typed states, including optional profile-specific resources.
    pub fn from_states(states: impl IntoIterator<Item = LoadState>) -> Self {
        let mut status = Self { all_loaded: true, loading: false, error: false };

        for state in states {
            status.all_loaded &= state == LoadState::Loaded;
            status.loading |= state == LoadState::Loading;
            status.error |= state == LoadState::Err;
        }

        status
    }

    /// Include another profile-required resource in this aggregate.
    pub fn include(&mut self, state: LoadState) {
        self.all_loaded &= state == LoadState::Loaded;
        self.loading |= state == LoadState::Loading;
        self.error |= state == LoadState::Err;
    }
}

/// Protocol run state together with the profile's resource readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationStatus {
    pub run_state: RunState,
    pub resources: LoadStatus,
}

impl ApplicationStatus {
    /// Common resource set for System B and System 7.
    ///
    /// Custom profiles may extend or replace this via
    /// `StackDefinition::application_status`.
    pub fn from_state(
        state: &(impl HasApplication + HasAddressTable + HasAssociationTable + HasCommunicationObjectTable),
    ) -> Self {
        Self {
            run_state: state.app().borrow().run_state(),
            resources: LoadStatus::from_states([
                state.adt().borrow().load_state(),
                state.ast().borrow().load_state(),
                state.cot().borrow().load_state(),
                state.app().borrow().load_state(),
            ]),
        }
    }

    /// Whether application outputs may use the current configuration.
    ///
    /// This does not change the wire-visible run state or promise persistence.
    pub fn is_operational(&self) -> bool {
        self.run_state == RunState::Running && self.resources.all_loaded
    }
}

/// Save progress reported by the shared persistence manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceStatus {
    /// Current volatile configuration revision.
    pub revision: u32,
    /// Unsaved changes, including changes received while saving.
    pub dirty: bool,
    /// Revision currently being persisted, if any.
    pub saving: Option<u32>,
    /// Wrapping failure counter; later successful saves do not erase history.
    pub failures: u32,
    /// An accepted restart is waiting for persistence and response draining.
    pub restarting: bool,
}

/// Current authoritative application and configuration status.
///
/// Notifications carry this complete snapshot. A slow or late subscriber can
/// always recover current state without reconstructing a sequence of events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStatus {
    pub application: ApplicationStatus,
    pub persistence: PersistenceStatus,
}

#[cfg(all(test, feature = "tp1"))]
mod tests {
    use core::cell::RefCell;

    use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
    use zweidraehte_proto::{
        AccessContext,
        address::IndividualAddress,
        device::{DeviceDescriptor, MaskVersion},
    };

    use super::*;
    use crate::{
        DeviceDefinition, HasPersistence, NoParams, StackDefinition, StackResources, StackState,
        bcus::system_b::{SystemBStateInit, Tp1},
        config::buffer_size_for_apdu,
        layers::linklayers::mock::{InjectedFrame, MockLinkLayerBuilder},
        objects::{
            comm::NoComObjects,
            interface::{FullPropertyWriteRequest, PropertyServiceHandler, pid},
            tables::{LoadEvent, RunEvent},
        },
        storage::StaticIdentity,
    };

    const DEVICE: DeviceDescriptor =
        DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 1, 1, 1, 1, 0);

    struct BrightnessDevice;

    impl DeviceDefinition for BrightnessDevice {
        const DEVICE: &'static DeviceDescriptor = &DEVICE;

        type Params = NoParams;
        type ComObjects = NoComObjects;
        type LinkLayer = MockLinkLayerBuilder<1>;
    }

    type Definition = Tp1<BrightnessDevice>;

    fn stack() -> crate::Stack<'static, Definition> {
        const BUFFER_SIZE: usize = buffer_size_for_apdu(<Definition as StackDefinition>::MAX_APDU_LENGTH);

        let resources = Box::leak(Box::new(StackResources::<Definition, BUFFER_SIZE, 4>::new()));
        let injection = Box::leak(Box::new(Channel::<NoopRawMutex, InjectedFrame, 1>::new()));
        let (link, _) = MockLinkLayerBuilder::new(injection);
        let (stack, _) = crate::new(
            resources,
            link,
            SystemBStateInit::new(StaticIdentity::new([0; 6]), None),
            (),
            Definition::memory_map(),
            (),
        );

        stack
    }

    fn load<T: HasLoadStateMachine>(resource: &RefCell<T>) {
        let mut resource = resource.borrow_mut();

        resource.write_lsm(&[LoadEvent::StartLoading.into()], None);
        resource.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        assert!(resource.is_loaded());
    }

    #[test]
    fn application_readiness_requires_every_table_and_survives_no_run_state_event() {
        let stack = stack();
        let state = stack.state();

        load(state.app());
        state.app().borrow_mut().handle_run_event(RunEvent::Loaded);
        state.app().borrow_mut().handle_run_event(RunEvent::ReadyToRun);

        assert!(stack.is_running());
        assert!(!stack.status().application.is_operational());

        load(state.adt());
        load(state.ast());

        assert!(!stack.status().application.is_operational());

        load(state.cot());

        assert!(stack.status().application.is_operational());

        state.ast().borrow_mut().write_lsm(&[LoadEvent::StartLoading.into()], None);

        assert!(stack.is_running(), "table loading does not rewrite the APP RSM");
        assert!(!stack.status().application.is_operational());
        assert!(stack.status().application.resources.loading);

        state.reset_association_table();

        assert!(!stack.status().application.is_operational());
        assert!(!stack.status().application.resources.loading);
    }

    #[test]
    fn first_download_and_errors_are_visible_without_application_started_or_stopped() {
        let stack = stack();

        assert!(!stack.is_running());

        stack.state().adt().borrow_mut().write_lsm(&[LoadEvent::StartLoading.into()], None);

        assert!(stack.status().application.resources.loading);
        assert!(!stack.status().application.is_operational());

        let aggregate = LoadStatus::from_states([LoadState::Loading, LoadState::Err]);

        assert!(aggregate.loading);
        assert!(aggregate.error);
        assert!(!aggregate.all_loaded);
    }

    #[test]
    fn late_and_slow_watchers_receive_current_state_and_independent_notifications() {
        let stack = stack();

        stack.set_individual_address(IndividualAddress::new(1, 2, 3));

        let mut first = stack.watch_status().expect("first watcher");
        let mut second = stack.watch_status().expect("second watcher");

        assert_eq!(first.try_get(), Some(stack.status()));
        assert_eq!(second.try_get(), Some(stack.status()));
        assert_eq!(first.try_changed(), None);

        // More updates than the old lifecycle event queue could retain.
        for address in 4..20 {
            stack.set_individual_address(IndividualAddress::new(1, 2, address));
        }

        assert_eq!(first.try_changed(), Some(stack.status()));
        assert_eq!(second.try_changed(), Some(stack.status()));
        assert_eq!(first.try_changed(), None);

        stack.publish_status();

        assert_eq!(first.try_changed(), None, "an unchanged snapshot is not progress");
    }

    #[test]
    fn rejected_writes_and_programming_mode_do_not_advance_configuration_revision() {
        let stack = stack();
        let revision = stack.state().config_revision();

        let mut request = FullPropertyWriteRequest {
            object_idx: 0,
            pid: pid::device::PROGMODE,
            count: 1,
            start_idx: 1,
            data: &[1],
            ctx: AccessContext::MAX_ACCESS,
        };

        stack.interface_objects.property_value_write(&request).expect("programming mode is writable");

        assert!(stack.state().is_programming_mode());
        assert_eq!(stack.state().config_revision(), revision);
        assert!(!stack.state().is_dirty());

        request.object_idx = 1;
        request.pid = pid::OBJECT_TYPE;

        assert!(stack.interface_objects.property_value_write(&request).is_err());
        assert_eq!(stack.state().config_revision(), revision);

        request.pid = pid::LOAD_STATE_CONTROL;

        stack.interface_objects.property_value_write(&request).expect("start loading is accepted");

        assert_ne!(stack.state().config_revision(), revision);
        assert!(stack.status().application.resources.loading);
    }
}
