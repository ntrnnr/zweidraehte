//! Transient stack context bundle passed to link layers.
//!
//! [`StackContext`] is assembled at [`Runner::run`](crate::Runner::run)
//! scope and handed to link-layer builders through
//! [`LinkLayerBuilder::build_and_run`](crate::layers::LinkLayerBuilder::build_and_run).
//!
//! # Why this is transient, not stored on `StackCore`
//!
//! `StackCore` owns the device
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

use core::cell::RefCell;

use crate::objects::interface::{HasMaxRetryCount, HasRfDomainAddress, HasRfRetransmitter};
#[cfg(feature = "knxip")]
use crate::{
    HasAdditionalIas, HasExtensionState, HasIpExtensionState, HasPersistence, HasRoutingMulticastRebind, IpPlatform,
    ip::HasIpSecureView,
    layers::linklayers::knxip::context::{
        DeviceInfoContext, IpAdditionalIndividualAddressContext, IpConfigWriteContext, IpDiagnosticsContext,
        IpSecureConfigContext, RemoteRestartContext, RoutingMulticastRebindContext,
    },
    storage::StorageHooks,
};
use crate::{
    StackState,
    context::{
        AddressTableContext, ApduLengthContext, BufferManagerContext, IndividualAddressContext, MaxRetryCountContext,
        PropertyServiceContext, RfDomainAddressContext, RfRetransmitterContext, layer::LayerContext,
    },
    definition::StackDefinition,
    objects::tables::HasAddressTable,
    prelude::PropertyServiceHandler,
    stack_core::StackCore,
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

/// Construction-time context bundle — exists only inside
/// [`Runner::run`](crate::Runner::run).
///
/// Bundles references to the stack core (state, platform, memory map) and
/// [`InterfaceObjects`](crate::StackDefinition::InterfaceObjects). Two
/// consumers: layer constructors capture their long-lived references from
/// it (`NetworkLayer::new(ctx)` etc.), and link layers receive it through
/// [`LinkLayerBuilder::build_and_run`](crate::layers::LinkLayerBuilder::build_and_run)
/// as the carrier of the context traits implemented below. It is *not* a
/// per-request context — that role belongs to
/// [`ServiceCtx`](crate::service::ServiceCtx) /
/// [`AlCtx`](crate::service::AlCtx).
///
/// See the module-level docs for why this is transient rather than a field
/// on `StackCore`.
pub struct StackContext<'a, D: StackDefinition> {
    pub(crate) inner: &'a StackCore<D>,
    pub(crate) interface_objects: &'a D::InterfaceObjects<'static>,
}

impl<'a, D: StackDefinition> StackContext<'a, D> {
    /// Construct a new transient bundle. Caller (the
    /// [`Runner`](crate::Runner)) owns both references separately to avoid
    /// the self-referential problem described in the module docs.
    pub(crate) fn new(inner: &'a StackCore<D>, interface_objects: &'a D::InterfaceObjects<'static>) -> Self {
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

/// Expose the IP extension state's write side to the remote-config server
/// (`REMOTE_BASIC_CONFIGURATION_REQUEST`). `IpCapableStack` already bounds
/// `ES: HasIpExtensionState`, so `ip_state()` is available; the extra
/// `HasPersistence` bound on `D::State` lets us mark the write dirty.
#[cfg(feature = "knxip")]
impl<D: IpCapableStack> IpConfigWriteContext for StackContext<'_, D>
where
    D::State: HasPersistence,
{
    fn ip_state_mut(&self) -> &dyn crate::ip::IpStateView {
        self.inner.state.extension_state().ip_state()
    }

    fn mark_config_dirty(&self) {
        self.inner.state.mark_dirty();
    }
}

/// Forward the extension state's KNX IP Secure configuration (PIDs
/// 91–97) to the link layer. The `HasIpSecureView` bound is satisfied
/// by every IP extension state — its default returns `None`, and only
/// the secure IP extension overrides it — so this impl (and thereby the
/// `KnxNetIpContext` blanket) stays unconditional for non-secure IP
/// devices. The `StorageHooks` bound is likewise satisfied by every
/// storage handle (and by the storage-less `()`), and only the
/// `ip-secure` mc_timer methods reach through it.
#[cfg(feature = "knxip")]
impl<D: IpCapableStack> IpSecureConfigContext for StackContext<'_, D>
where
    <D::State as HasExtensionState>::ES: HasIpSecureView,
    D::Storage: StorageHooks,
{
    fn ip_secure_view(&self) -> Option<&dyn crate::ip::IpSecureStateView> {
        self.inner.state.extension_state().ip_secure_view()
    }

    fn knx_serial_number(&self) -> [u8; 6] {
        *self.inner.state.serial_number()
    }

    #[cfg(feature = "ip-secure")]
    fn load_mc_timer(&self) -> u64 {
        self.inner.layer_context.storage.load_mc_timer()
    }

    #[cfg(feature = "ip-secure")]
    fn save_mc_timer(&self, value: u64) {
        self.inner.layer_context.storage.save_mc_timer(value);
    }
}

/// Forward the remote-reset server's restart request onto the same restart
/// channel the Application Layer uses for `A_Restart`, so user code drains
/// one queue for both. Reaches the channel through the `LayerContext`'s
/// inherent `try_send_restart_request` helper.
#[cfg(feature = "knxip")]
impl<D: IpCapableStack> RemoteRestartContext for StackContext<'_, D> {
    fn request_restart(&self, request: crate::restart::RestartRequest) -> bool {
        self.inner.layer_context.try_send_restart_request(request)
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
impl<D: StackDefinition> IndividualAddressContext for StackContext<'_, D> {
    fn individual_address(&self) -> zweidraehte_proto::address::IndividualAddress {
        self.inner.state.individual_address()
    }
}

impl<D: StackDefinition> AddressTableContext for StackContext<'_, D> {
    type ADT = <D::State as HasAddressTable>::ADT;

    fn address_table(&self) -> &RefCell<Self::ADT> {
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

// Only present when the device composes the optional retransmitter extension
// (`D::State: HasRfRetransmitter`). This is the compile-time gate that lets the
// `RetransmitEnabled` KNX-RF link-layer policy read the retransmitter
// parameters; non-retransmitter devices never satisfy the bound, so the
// repeating link layer cannot be selected without the extension.
impl<D: StackDefinition> RfRetransmitterContext for StackContext<'_, D>
where
    D::State: HasRfRetransmitter,
{
    fn rf_retransmit_enabled(&self) -> bool {
        self.inner.state.rf_retransmit_enabled()
    }

    fn rf_repeat_counter_limit(&self) -> u8 {
        self.inner.state.rf_repeat_counter_limit()
    }
}
