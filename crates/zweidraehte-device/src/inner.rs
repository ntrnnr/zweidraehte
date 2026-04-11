//! Internal stack state and runtime context types.
//!
//! [`Inner`] holds all shared state for a running KNX stack instance.
//! [`StackContext`] is the runtime context passed to link layers, providing
//! access to buffer management, property services, and device information.

#[cfg(feature = "knxip")]
use crate::bcus::system_b::HasExtensionState;
use crate::{
    StackState,
    context::{BufferManagerContext, PropertyServiceContext},
    definition::StackDefinition,
    layer_context::LayerContext,
    messages::buffers::DynBufferManager,
    objects::{comm::HasCommObjects, tables::HasAddressTable},
    prelude::PropertyServiceHandler,
};

// ============================================================================
// APDU length clamping helper
// ============================================================================

/// Clamp and set the runtime APDU length, warning if the value exceeds the
/// compile-time buffer allocation.
fn set_clamped_apdu_length<D: StackDefinition>(state: &D::State, length: u16) {
    let clamped = length.min(D::MAX_APDU_LENGTH);
    if clamped < length {
        warn!("set_max_apdu_length({}) clamped to StackDefinition::MAX_APDU_LENGTH ({})", length, D::MAX_APDU_LENGTH);
    }
    state.set_max_apdu_length(clamped);
}

// ============================================================================
// IpCapableStack — bound bundle for IP context traits
// ============================================================================

/// Bound bundle for stack definitions with full IP context support.
///
/// Auto-implemented via blanket impl. Simplifies where clauses on
/// [`StackContext`] trait impls that need IP extension state and platform.
#[cfg(feature = "knxip")]
pub trait IpCapableStack:
    StackDefinition<State: HasExtensionState<ES: crate::IpStackState>, Platform: crate::IpPlatform>
{
}

#[cfg(feature = "knxip")]
impl<D> IpCapableStack for D
where
    D: StackDefinition,
    D::State: HasExtensionState,
    <D::State as HasExtensionState>::ES: crate::IpStackState,
    D::Platform: crate::IpPlatform,
{
}

// ============================================================================
// Inner
// ============================================================================

/// Core stack interior: state + platform + memory map.
pub(crate) struct Inner<D: StackDefinition> {
    /// Unified device state containing runtime state, tables, and configuration.
    pub(crate) state: D::State,
    /// Platform abstraction for querying/applying network configuration.
    ///
    /// For KNX/IP devices this provides current IP, MAC, capabilities, etc.
    /// For non-IP devices this is `()`.
    pub(crate) platform: D::Platform,
    /// Memory map for A_Memory_Read/Write services.
    pub(crate) memory_map: D::Mem,
    /// Shared runtime infrastructure.
    pub(crate) layer_context: &'static LayerContext<D>,
}

impl<D: StackDefinition> Inner<D> {
    /// Execute a closure with mutable access to communication objects.
    /// Ensures the borrow is properly scoped and released.
    pub(crate) fn with_comm_objs<R>(&self, f: impl FnOnce(&mut D::CO) -> R) -> R {
        let mut comm_objs = self.state.comm_objects().borrow_mut();
        f(&mut comm_objs)
    }
}

// ============================================================================
// StackContext
// ============================================================================

/// Runtime context passed to link layers during [`Runner::run()`](crate::Runner::run).
///
/// Combines buffer management and property service access into a single
/// reference that link layers receive through
/// [`LinkLayerBuilder::build_and_run`](crate::layers::LinkLayerBuilder::build_and_run).
/// Link layers access capabilities via the [`BufferManagerContext`] and
/// [`PropertyServiceContext`](crate::context::PropertyServiceContext) trait impls.
pub struct StackContext<'a, D: StackDefinition> {
    pub(crate) inner: &'a Inner<D>,
    pub(crate) interface_objects: &'a D::InterfaceObjects<'static>,
}

impl<D: StackDefinition> BufferManagerContext for StackContext<'_, D> {
    fn buffer_manager(&self) -> &DynBufferManager<'static> {
        &self.inner.layer_context.buffer_manager
    }
}

impl<D: StackDefinition> crate::context::ApduLengthContext for StackContext<'_, D> {
    fn max_apdu_length(&self) -> u16 {
        self.inner.state.max_apdu_length()
    }

    fn set_max_apdu_length(&self, length: u16) {
        set_clamped_apdu_length::<D>(&self.inner.state, length);
    }
}

impl<D: StackDefinition> PropertyServiceContext for StackContext<'_, D> {
    fn property_handler(&self) -> &dyn PropertyServiceHandler {
        self.interface_objects
    }
}

#[cfg(feature = "knxip")]
impl<D: IpCapableStack> crate::layers::linklayers::knxip::context::DeviceInfoContext for StackContext<'_, D> {
    fn device_information(&self) -> crate::messages::knxip::substructs::DeviceInformation {
        use crate::IpPlatform;
        use crate::IpStackState;
        use crate::bcus::system_b::HasExtensionState;
        use crate::messages::knxip::substructs::{
            DeviceInformation, DeviceStatus, ExtendedDeviceInformation, KNXMedium,
        };
        use zweidraehte_platform::address::EthernetAddress;

        let state = &self.inner.state;
        let ip = state.extension_state();
        let platform = &self.inner.platform;

        DeviceInformation {
            medium: KNXMedium::KNXIP,
            device_status: if state.is_programming_mode() { DeviceStatus::ProgrammingMode } else { DeviceStatus::None },
            individual_address: state.individual_address(),
            project_installation_identifier: ip.project_installation_id(),
            knx_serial_number: *state.serial_number(),
            routing_multicast_address: ip.routing_multicast_address(),
            mac_address: EthernetAddress(platform.mac_address()),
            friendly_name: ip.friendly_name(),
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
impl<D: IpCapableStack> crate::layers::linklayers::knxip::context::IpDiagnosticsContext for StackContext<'_, D> {
    fn ip_config(&self) -> crate::messages::knxip::substructs::IpConfig {
        use crate::IpPlatform;
        use crate::IpStackState;
        use crate::bcus::system_b::HasExtensionState;

        let ip = self.inner.state.extension_state();
        let platform = &self.inner.platform;
        crate::messages::knxip::substructs::IpConfig {
            ip_address: ip.configured_ip_address(),
            subnet_mask: ip.configured_subnet_mask(),
            default_gateway: ip.configured_default_gateway(),
            ip_capabilities: platform.ip_capabilities(),
            ip_assignment_method: ip.ip_assignment_method(),
        }
    }

    fn ip_current_config(&self) -> crate::messages::knxip::substructs::IpCurrentConfig {
        use crate::IpPlatform;

        let platform = &self.inner.platform;
        crate::messages::knxip::substructs::IpCurrentConfig {
            ip_address: platform.current_ip_address(),
            subnet_mask: platform.current_subnet_mask(),
            default_gateway: platform.current_default_gateway(),
            // TODO: Track DHCP server address when DHCP is implemented
            dhcp_server: core::net::Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: platform.current_ip_assignment_method(),
        }
    }
}

#[cfg(feature = "knxip")]
impl<D: IpCapableStack> crate::layers::linklayers::knxip::context::IpAdditionalIndividualAddressContext for StackContext<'_, D> {
    fn write_additional_individual_addresses(&self, buf: &mut [crate::address::IndividualAddress]) -> usize {
        use crate::IpStackState;
        use crate::bcus::system_b::HasExtensionState;
        self.inner.state.extension_state().write_additional_individual_addresses(buf)
    }
}

impl<D: StackDefinition> crate::context::MaxRetryCountContext for StackContext<'_, D>
where
    D::State: crate::objects::interface::HasMaxRetryCount,
{
    fn max_retry_count(&self) -> u8 {
        use crate::objects::interface::HasMaxRetryCount;
        self.inner.state.max_retry_count()
    }
}

// Unconditional — `individual_address()` is on `StackState`, so this works
// for both IP and TP1 devices.
impl<D: StackDefinition> crate::context::KnxIndividualAddressContext for StackContext<'_, D> {
    fn individual_address(&self) -> crate::address::IndividualAddress {
        self.inner.state.individual_address()
    }
}

impl<D: StackDefinition> crate::context::AddressTableContext for StackContext<'_, D> {
    type ADT = <D::State as crate::objects::tables::HasAddressTable>::ADT;

    fn address_table(&self) -> &core::cell::RefCell<Self::ADT> {
        self.inner.state.adt()
    }
}
