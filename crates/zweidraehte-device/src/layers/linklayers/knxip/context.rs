//! Context traits for KNX/IP link layer and services.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knxip::substructs::{DeviceInformation, ExtendedDeviceInformation};

/// Provides access to dynamic device information for KNX/IP discovery.
///
/// Implemented by the stack's runtime context so the KNX/IP link layer
/// can build fresh [`DeviceInformation`] on each discovery request,
/// reflecting current programming mode, individual address, etc.
///
/// Only implemented when the device state is `IpStackState`,
/// since discovery is a KNX/IP-only concept.
pub trait DeviceInfoContext {
    /// Build a [`DeviceInformation`] reflecting the current device state.
    fn device_information(&self) -> DeviceInformation;

    /// Build an [`ExtendedDeviceInformation`] reflecting the current device state.
    ///
    /// Used in `SearchResponseExtended` (spec §7.6.3.6). Contains medium status,
    /// max local APDU length, and device descriptor type 0.
    fn extended_device_information(&self) -> ExtendedDeviceInformation;

    /// The KNX manufacturer code (big-endian, 2 bytes).
    ///
    /// Used by tunneling feature responses (spec 03/08/04 §4.6).
    fn manufacturer_code(&self) -> u16;
}

/// Provides IP diagnostics data for remote configuration responses.
///
/// The remote diagnostic server (KNX 3/8/7) must include IP_CONFIG,
/// IP_CUR_CONFIG, and KNX_ADDRESSES DIBs in its responses. This trait
/// abstracts the data source so the server doesn't depend on
/// `IpStackState` directly.
///
/// Only relevant for KNX/IP devices. Implementations should query the
/// device state and platform for current network configuration.
pub trait IpDiagnosticsContext {
    /// Build an `IpConfig` DIB from configured (ETS-programmed) values.
    fn ip_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpConfig;

    /// Build an `IpCurrentConfig` DIB from the platform's current state.
    fn ip_current_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig;
}

/// Exposes the routing-multicast-rebind channel that the write-handler
/// side of the stack (`IpExtensionState::set_*`) uses to ask the KNX/IP
/// link-layer task to rejoin the multicast group
/// (03/02/06 §4.3.5.3.5.1).
///
/// Only IP stacks implement this; the runtime reaches it through
/// [`KnxNetIpContext`](super::KnxNetIpContext).
pub trait RoutingMulticastRebindContext {
    /// The channel drained by the KNX/IP runtime's main select loop.
    fn routing_multicast_rebind_channel(&self) -> &Channel<NoopRawMutex, core::net::Ipv4Addr, 2>;
}

/// Provides additional KNX individual addresses for IP tunneling use-cases.
///
/// Uses a write-to-buffer pattern instead of returning a fixed-capacity Vec,
/// so the caller controls the buffer size (typically `N` from the tunnel
/// connection handler's const generic).
pub trait IpAdditionalIndividualAddressContext {
    /// Write additional individual addresses into `buf`.
    ///
    /// Returns the number of addresses written (`<= buf.len()`).
    fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize;
}
