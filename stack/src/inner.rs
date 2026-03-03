//! Internal stack state and runtime context types.
//!
//! [`Inner`] holds all shared state for a running KNX stack instance.
//! [`StackContext`] is the runtime context passed to link layers, providing
//! access to buffer management, property services, and device information.

use core::cell::RefCell;

use embassy_sync::{
    channel::Channel,
    pubsub::PubSubChannel,
};

use crate::{
    actor::Request,
    context::BufferManagerContext,
    definition::StackDefinition,
    layers::application::{ApplicationLayerService, ApplicationLayerServiceResponse},
    messages::buffers::DynBufferManager,
    objects::{
        comm::{ComObjectEvent, ComObjects, LifecycleEvent},
        tables::HasAddressTable,
    },
    restart,
    StackState,
};

#[cfg(feature = "knxip")]
use crate::IpStackState;

// ============================================================================
// Inner
// ============================================================================

pub(crate) struct Inner<D: StackDefinition> {
    pub(crate) buffer_manager: DynBufferManager<'static>,
    // These channels are shared between the stack runner task and user code
    // (e.g. `Stack::update_object`, `restart_task`). They use `D::Mutex` so
    // users can pick `CriticalSectionRawMutex` when the stack runs on an
    // `InterruptExecutor` that can preempt the user's thread executor.
    pub(crate) app_service_channel:
        Channel<D::Mutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,
    pub(crate) comm_objs: RefCell<D::CO>,
    pub(crate) event_channel:
        PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
    /// Channel for application lifecycle events (started/stopped running)
    pub(crate) lifecycle_channel: PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
    /// Channel for A_Restart requests from application layer to user code.
    ///
    /// In the synchronous router model, AL sends the bus response immediately
    /// and fires off the request to user code. User code receives it and
    /// performs the actual restart/reset — no response channel needed.
    pub(crate) restart_channel: Channel<D::Mutex, restart::RestartRequest, 1>,
    /// Unified device state containing runtime state, tables, and configuration
    pub(crate) state: D::State,
    /// Hook context for communication object hooks
    pub(crate) hook_context: <D::CO as ComObjects>::HookContext,
    /// Memory map for A_Memory_Read/Write services
    pub(crate) memory_map: D::Mem,
}

impl<D: StackDefinition> Inner<D> {
    /// Execute a closure with mutable access to communication objects.
    /// Ensures the borrow is properly scoped and released.
    pub(crate) fn with_comm_objs<R>(&self, f: impl FnOnce(&mut D::CO) -> R) -> R {
        let mut comm_objs = self.comm_objs.borrow_mut();
        f(&mut comm_objs)
    }
}

// Implement context traits for Inner
impl<D: StackDefinition> BufferManagerContext for &Inner<D> {
    fn buffer_manager(&self) -> &DynBufferManager<'static> {
        &self.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        self.state.max_apdu_length()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.state.set_max_apdu_length(length);
    }
}

// ============================================================================
// StackContext
// ============================================================================

/// Combined context passed to [`LinkLayerBuilder::build_and_run()`](crate::layers::LinkLayerBuilder::build_and_run).
///
/// Wraps references to the stack's internal state (for buffer management)
/// and interface objects (for property service access). Created in
/// [`Runner::run()`](crate::Runner::run) where both are available.
/// Runtime context passed to link layers during [`Runner::run()`](crate::Runner::run).
///
/// This is an opaque wrapper combining buffer management and property service
/// access. Link layers receive a `&StackContext` through
/// [`LinkLayerBuilder::build_and_run`](crate::layers::LinkLayerBuilder::build_and_run)
/// and access its capabilities via the [`BufferManagerContext`] and
/// [`PropertyServiceContext`](crate::context::PropertyServiceContext) trait impls.
pub struct StackContext<'a, D: StackDefinition> {
    pub(crate) inner: &'a Inner<D>,
    pub(crate) interface_objects: &'a D::InterfaceObjects<'static>,
}

impl<D: StackDefinition> BufferManagerContext for StackContext<'_, D> {
    fn buffer_manager(&self) -> &DynBufferManager<'static> {
        &self.inner.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        self.inner.state.max_apdu_length()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.inner.state.set_max_apdu_length(length);
    }
}

impl<D: StackDefinition> crate::context::PropertyServiceContext for StackContext<'_, D> {
    fn property_handler(&self) -> &dyn crate::objects::interface::PropertyServiceHandler {
        self.interface_objects
    }
}

#[cfg(feature = "knxip")]
impl<D: StackDefinition> crate::context::DeviceInfoContext for StackContext<'_, D>
where
    D::State: crate::IpStackState,
{
    fn device_information(&self) -> crate::messages::knxip::substructs::DeviceInformation {
        use crate::messages::knxip::substructs::{DeviceInformation, DeviceStatus, KNXMedium};
        use platform::address::EthernetAddress;

        let state = &self.inner.state;
        let mut friendly_name = [0u8; 30];
        state.friendly_name(&mut friendly_name);

        DeviceInformation {
            medium: KNXMedium::KNXIP,
            device_status: if state.is_programming_mode() { DeviceStatus::ProgrammingMode } else { DeviceStatus::None },
            individual_address: state.individual_address(),
            project_installation_identifier: state.project_installation_id(),
            knx_serial_number: *state.serial_number(),
            routing_multicast_address: state.routing_multicast_address(),
            mac_address: EthernetAddress(state.mac_address()),
            friendly_name,
        }
    }

    fn extended_device_information(&self) -> crate::messages::knxip::substructs::ExtendedDeviceInformation {
        crate::messages::knxip::substructs::ExtendedDeviceInformation {
            // Spec §7.5.4.9: medium_status bit 0 = COMMUNICATION_IMPOSSIBLE.
            // For non-router KNX/IP devices, this is always FALSE (0x00).
            medium_status: 0x00,
            max_local_apdu_len: self.inner.state.max_apdu_length(),
            device_descriptor_type0: D::DEVICE.mask_version.as_u16(),
        }
    }

    fn manufacturer_code(&self) -> u16 {
        D::DEVICE.manufacturer_id
    }
}

#[cfg(feature = "knxip")]
impl<D: StackDefinition> crate::context::IpDiagnosticsContext for StackContext<'_, D>
where
    D::State: crate::IpStackState,
{
    fn ip_config(&self) -> crate::messages::knxip::substructs::IpConfig {
        let state = &self.inner.state;
        crate::messages::knxip::substructs::IpConfig {
            ip_address: state.configured_ip_address(),
            subnet_mask: state.configured_subnet_mask(),
            default_gateway: state.configured_default_gateway(),
            ip_capabilities: state.ip_capabilities(),
            ip_assignment_method: state.ip_assignment_method(),
        }
    }

    fn ip_current_config(&self) -> crate::messages::knxip::substructs::IpCurrentConfig {
        let state = &self.inner.state;
        crate::messages::knxip::substructs::IpCurrentConfig {
            ip_address: state.current_ip_address(),
            subnet_mask: state.current_subnet_mask(),
            default_gateway: state.current_default_gateway(),
            // TODO: Track DHCP server address in IpStackState when DHCP is implemented
            dhcp_server: core::net::Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: state.current_ip_assignment_method(),
        }
    }
}

#[cfg(feature = "knxip")]
impl<D: StackDefinition> crate::context::IpAdditionalIndividualAddressContext for StackContext<'_, D>
where
    D::State: crate::IpStackState,
{
    fn write_additional_individual_addresses(&self, buf: &mut [crate::address::IndividualAddress]) -> usize {
        self.inner.state.write_additional_individual_addresses(buf)
    }
}

// Unconditional — `individual_address()` is on `StackState`, so this works
// for both IP and TP1 devices.
impl<D: StackDefinition> crate::context::KnxIndividualAddressContext for StackContext<'_, D> {
    fn individual_address(&self) -> crate::address::IndividualAddress {
        self.inner.state.individual_address()
    }
}

impl<D: StackDefinition> crate::context::AddressTableContext for StackContext<'_, D>
where
    D::State: crate::objects::tables::HasAddressTable,
{
    type ADT = <D::State as crate::objects::tables::HasAddressTable>::ADT;

    fn address_table(&self) -> &core::cell::RefCell<Self::ADT> {
        self.inner.state.adt()
    }
}
