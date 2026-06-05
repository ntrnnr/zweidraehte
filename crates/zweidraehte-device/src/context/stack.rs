//! Transient stack context bundle passed to link layers.
//!
//! [`StackContext`] is assembled at [`Runner::run`](crate::Runner::run)
//! scope and handed to link-layer builders through
//! [`LinkLayerBuilder::build_and_run`](crate::layers::LinkLayerBuilder::build_and_run).
//!
//! # Why this is transient, not stored on `Inner`
//!
//! [`Inner`](crate::inner::Inner) owns the device
//! [`State`](crate::StackDefinition::State). The
//! [`InterfaceObjects`](crate::StackDefinition::InterfaceObjects) container
//! borrows from that state (`&'a D::State` for property accessors, table
//! references, etc.). If `StackContext` lived as a field on `Inner`, we
//! would have a self-referential struct — `Inner` owning both `state` and
//! something that borrows from `state`. That's why the bundle is
//! constructed on the stack in `Runner::run` with both halves as separate
//! `&'static` references, and context-trait impls live here on the
//! transient view.
//!
//! Do not try to collapse this back into `Inner`; a prior attempt hit
//! exactly the self-referential wall.

#[cfg(feature = "knxip")]
use crate::bcus::system_b::HasExtensionState;
use crate::objects::interface::{HasMaxRetryCount, HasRfDomainAddress};
#[cfg(feature = "knxip")]
use crate::{
    HasAdditionalIas, HasIpExtensionState, HasRoutingMulticastRebind, IpPlatform,
    layers::linklayers::knxip::context::{
        DeviceInfoContext, IpAdditionalIndividualAddressContext, IpDiagnosticsContext, RoutingMulticastRebindContext,
    },
};
use crate::{
    StackState,
    context::{
        AddressTableContext, ApduLengthContext, BufferManagerContext, KnxIndividualAddressContext,
        MaxRetryCountContext, PropertyServiceContext, RfDomainAddressContext, layer::LayerContext,
    },
    definition::StackDefinition,
    inner::Inner,
    objects::tables::HasAddressTable,
    prelude::PropertyServiceHandler,
};
use zweidraehte_proto::messages::buffers::DynBufferManager;

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
    StackDefinition<State: HasExtensionState<ES: HasIpExtensionState>, Platform: IpPlatform>
{
}

#[cfg(feature = "knxip")]
impl<D> IpCapableStack for D
where
    D: StackDefinition,
    D::State: HasExtensionState,
    <D::State as HasExtensionState>::ES: HasIpExtensionState,
    D::Platform: IpPlatform,
{
}

// ============================================================================
// StackContext
// ============================================================================

/// Runtime context passed to link layers during
/// [`Runner::run`](crate::Runner::run).
///
/// Bundles references to [`Inner`] (state, platform, memory map) and
/// [`InterfaceObjects`](crate::StackDefinition::InterfaceObjects) into a
/// single value that link layers receive through
/// [`LinkLayerBuilder::build_and_run`](crate::layers::LinkLayerBuilder::build_and_run).
///
/// See the module-level docs for why this is transient rather than a field
/// on [`Inner`].
pub struct StackContext<'a, D: StackDefinition> {
    pub(crate) inner: &'a Inner<D>,
    pub(crate) interface_objects: &'a D::InterfaceObjects<'static>,
}

impl<'a, D: StackDefinition> StackContext<'a, D> {
    /// Construct a new transient bundle. Caller (the
    /// [`Runner`](crate::Runner)) owns both references separately to avoid
    /// the self-referential problem described in the module docs.
    pub(crate) fn new(inner: &'a Inner<D>, interface_objects: &'a D::InterfaceObjects<'static>) -> Self {
        Self { inner, interface_objects }
    }

    /// Access the unified device state.
    pub const fn state(&self) -> &'a D::State {
        &self.inner.state
    }

    /// Access the shared runtime infrastructure.
    pub const fn layer_context(&self) -> &'a LayerContext<D> {
        self.inner.layer_context
    }

    /// Access the interface objects container.
    pub const fn interface_objects(&self) -> &'a D::InterfaceObjects<'static> {
        self.interface_objects
    }

    /// Access the memory map for A_Memory_Read/Write services.
    pub const fn memory_map(&self) -> &'a D::Mem {
        &self.inner.memory_map
    }
}

impl<D: StackDefinition> BufferManagerContext for StackContext<'_, D> {
    fn buffer_manager(&self) -> &DynBufferManager<'static> {
        &self.inner.layer_context.buffer_manager
    }
}

impl<D: StackDefinition> ApduLengthContext for StackContext<'_, D> {
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
impl<D: IpCapableStack> DeviceInfoContext for StackContext<'_, D> {
    fn device_information(&self) -> zweidraehte_proto::messages::knxip::substructs::DeviceInformation {
        use zweidraehte_platform::address::EthernetAddress;
        use zweidraehte_proto::messages::knxip::substructs::{DeviceInformation, DeviceStatus, KNXMedium};

        let state = &self.inner.state;
        let ip = state.extension_state().ip_state();
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

    fn extended_device_information(&self) -> zweidraehte_proto::messages::knxip::substructs::ExtendedDeviceInformation {
        zweidraehte_proto::messages::knxip::substructs::ExtendedDeviceInformation {
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
impl<D: IpCapableStack> IpDiagnosticsContext for StackContext<'_, D> {
    fn ip_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpConfig {
        let ip = self.inner.state.extension_state().ip_state();
        let platform = &self.inner.platform;
        zweidraehte_proto::messages::knxip::substructs::IpConfig {
            ip_address: ip.configured_ip_address(),
            subnet_mask: ip.configured_subnet_mask(),
            default_gateway: ip.configured_default_gateway(),
            ip_capabilities: platform.ip_capabilities(),
            ip_assignment_method: ip.ip_assignment_method(),
        }
    }

    fn ip_current_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig {
        let platform = &self.inner.platform;
        zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig {
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
impl<D: IpCapableStack> IpAdditionalIndividualAddressContext for StackContext<'_, D>
where
    <D::State as HasExtensionState>::ES: HasAdditionalIas,
{
    fn write_additional_individual_addresses(
        &self,
        buf: &mut [zweidraehte_proto::address::IndividualAddress],
    ) -> usize {
        self.inner.state.extension_state().write_additional_ias_into(buf)
    }

    fn contains_additional_individual_address(&self, addr: zweidraehte_proto::address::IndividualAddress) -> bool {
        self.inner.state.extension_state().additional_ia_is_assigned(addr)
    }
}

/// Forward [`IpExtensionState`](crate::bcus::system_b::IpExtensionState)'s
/// rebind channel to the KNX/IP runtime's context trait. The `IpCapableStack`
/// + `HasRoutingMulticastRebind` bounds ensure this only applies to stacks
/// whose extension state actually carries the channel.
#[cfg(feature = "knxip")]
impl<D: IpCapableStack> RoutingMulticastRebindContext for StackContext<'_, D>
where
    <D::State as HasExtensionState>::ES: HasRoutingMulticastRebind,
{
    fn routing_multicast_rebind_channel(
        &self,
    ) -> &embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::net::Ipv4Addr, 2> {
        self.inner.state.extension_state().routing_multicast_rebind_channel()
    }
}

impl<D: StackDefinition> MaxRetryCountContext for StackContext<'_, D>
where
    D::State: HasMaxRetryCount,
{
    fn max_retry_count(&self) -> u8 {
        self.inner.state.max_retry_count()
    }
}

// Unconditional — `individual_address()` is on `StackState`, so this works
// for both IP and TP1 devices.
impl<D: StackDefinition> KnxIndividualAddressContext for StackContext<'_, D> {
    fn individual_address(&self) -> zweidraehte_proto::address::IndividualAddress {
        self.inner.state.individual_address()
    }
}

impl<D: StackDefinition> AddressTableContext for StackContext<'_, D> {
    type ADT = <D::State as HasAddressTable>::ADT;

    fn address_table(&self) -> &core::cell::RefCell<Self::ADT> {
        self.inner.state.adt()
    }
}

// Only stacks whose state stores an RF Domain Address (i.e. RF devices) get this
// impl. Serial number is always available via `StackState`.
impl<D: StackDefinition> RfDomainAddressContext for StackContext<'_, D>
where
    D::State: HasRfDomainAddress,
{
    fn rf_domain_address(&self, out: &mut [u8; 6]) {
        self.inner.state.rf_domain_address(out);
    }

    fn knx_serial_number(&self) -> [u8; 6] {
        *self.inner.state.serial_number()
    }
}
