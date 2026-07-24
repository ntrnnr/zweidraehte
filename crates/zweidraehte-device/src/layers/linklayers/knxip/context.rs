//! Context traits for KNX/IP link layer and services.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knxip::substructs::{DeviceInformation, ExtendedDeviceInformation};

use crate::ip::IpStateView;
use crate::restart::RestartRequest;

/// Provides access to dynamic device information for KNX/IP discovery.
///
/// Implemented by the stack's runtime context so the KNX/IP link layer
/// can build fresh [`DeviceInformation`] on each discovery request,
/// reflecting current programming mode, individual address, etc.
///
/// Only implemented when the device state is `IpStateView`,
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
/// `IpStateView` directly.
///
/// Only relevant for KNX/IP devices. Implementations should query the
/// device state and platform for current network configuration.
pub trait IpDiagnosticsContext {
    /// Build an `IpConfig` DIB from configured (ETS-programmed) values.
    fn ip_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpConfig;

    /// Build an `IpCurrentConfig` DIB from the platform's current state.
    fn ip_current_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig;
}

/// Write side of remote IP configuration (03/08/07 §4.4.3,
/// `REMOTE_BASIC_CONFIGURATION_REQUEST`).
///
/// The read side stays on [`IpDiagnosticsContext`]; this trait is kept
/// separate so the diagnostics interface remains read-only. The returned
/// [`IpStateView`] exposes the `set_*` mutators (interior-mutable `Cell`
/// fields, hence a shared `&self`). A write must be followed by
/// [`mark_config_dirty`](Self::mark_config_dirty) so the runtime persists
/// the change — the `IpStateView` setters deliberately do not mark the
/// device state dirty themselves.
pub trait IpConfigWriteContext {
    /// Borrow the persisted IP extension state to apply configuration writes.
    fn ip_state_mut(&self) -> &dyn IpStateView;

    /// Flag the device state as dirty so the runtime persists the IP
    /// configuration changes applied via [`ip_state_mut`](Self::ip_state_mut).
    fn mark_config_dirty(&self);
}

/// Lets the KNX/IP remote-reset server (03/08/07 §4.4.4,
/// `REMOTE_RESET_REQUEST`) raise the same [`RestartRequest`] the
/// Application Layer raises for `A_Restart`. Routing the remote reset
/// through the existing restart channel means user code handles it through
/// one unified path, rather than needing a second reset hook.
///
/// Only IP stacks implement this; the runtime reaches it through
/// `KnxNetIpContext`.
pub trait RemoteRestartContext {
    /// Publish a restart request. Returns `true` if it was enqueued
    /// (the channel has depth 1; a full channel means a restart is already
    /// pending, so dropping the duplicate is harmless).
    fn request_restart(&self, request: RestartRequest) -> bool;
}

/// Exposes the routing-multicast-rebind channel that the write-handler
/// side of the stack (`IpExtensionState::set_*`) uses to ask the KNX/IP
/// link-layer task to rejoin the multicast group
/// (03/02/06 §4.3.5.3.5.1).
///
/// Only IP stacks implement this; the runtime reaches it through
/// `KnxNetIpContext`.
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

    /// Whether `addr` is one of the additional individual addresses
    /// currently assigned to a tunneling slot. Read on the TPUART
    /// ACK hot path, so the implementation should avoid copying.
    fn contains_additional_individual_address(&self, addr: IndividualAddress) -> bool;
}

// ============================================================================
// IP Secure context
// ============================================================================

/// Bridges the device state's KNX IP Secure configuration
/// ([`IpSecureStateView`](crate::ip::IpSecureStateView), PIDs 91–97)
/// plus the KNX serial number into the link-layer context.
///
/// Part of `KnxNetIpContext` unconditionally:
/// the `StackContext` impl forwards to
/// [`HasIpSecureView`](crate::ip::HasIpSecureView), whose default
/// returns `None`, so non-secure IP devices satisfy the bound without
/// carrying secret storage. The secure dispatch path treats `None` as
/// "drop all secure traffic".
pub trait IpSecureConfigContext {
    /// The persisted IP Secure secrets, if the device carries them.
    fn ip_secure_view(&self) -> Option<&dyn crate::ip::IpSecureStateView>;

    /// The device's KNX serial number — sender identity in outgoing
    /// SECURE_WRAPPER security information blocks.
    fn knx_serial_number(&self) -> [u8; 6];

    /// The persisted mc_timer watermark (03/08/09 §2.2.4.2), read once
    /// before multicast timer sync starts. Direct store access through the
    /// storage handle — no message round-trip. Defaults to 0 for mock
    /// contexts.
    #[cfg(feature = "ip-secure")]
    fn load_mc_timer(&self) -> u64 {
        0
    }

    /// Persist an advanced mc_timer watermark, synchronously — the caller
    /// must not let a frame carrying a timer value beyond the previous
    /// watermark leave before this returns ("store immediately", 03/08/09
    /// §2.2.4.2). A save failure is logged and swallowed by the store:
    /// wedging secure routing on a broken backend is worse than the bounded
    /// replay-window risk. Defaults to a no-op for mock contexts.
    #[cfg(feature = "ip-secure")]
    fn save_mc_timer(&self, _value: u64) {}
}
