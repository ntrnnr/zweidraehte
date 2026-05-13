//! KNX/IP state extension
//!
//! This module contains IP-specific stack state accessors, constants, and
//! platform re-exports used by KNXnet/IP devices.
//!
//! The IP state surface lives on two distinct types:
//!
//! - The persisted/configured values (ETS-programmable: IP address, subnet,
//!   friendly name, project installation ID, etc.) live on
//!   [`IpExtensionState`](crate::bcus::system_b::IpExtensionState) as
//!   inherent methods. Code reaches them through the
//!   [`HasIpExtensionState`] accessor, which both `IpExtensionState` itself
//!   and the tunnelling-aggregating
//!   [`IpInterfaceExtension`](crate::bcus::system_b::IpInterfaceExtension)
//!   implement, so generic context impls navigate uniformly via
//!   `extension_state().ip_state()`.
//!
//! - Current runtime values (actual IP, MAC, link capabilities) live on the
//!   [`IpPlatform`] trait and are queried directly from the platform
//!   reference held by augments and context impls.

use core::net::Ipv4Addr;

use zweidraehte_proto::address::IndividualAddress;

// ============================================================================
// HasIpExtensionState — accessor for the canonical persisted IP config
// ============================================================================

/// Persisted IP configuration accessor surface.
///
/// Only [`IpExtensionState`](crate::bcus::system_b::IpExtensionState)
/// implements this trait directly — it carries the storage. Wrapper
/// types like
/// [`IpInterfaceExtension`](crate::bcus::system_b::IpInterfaceExtension)
/// expose the inner state via [`HasIpExtensionState`] instead, so
/// `IpStackState` has exactly one impl and never carries delegation.
///
/// Generic context code that needs to read IP config bounds
/// `ES: HasIpExtensionState` and calls `.ip_state()` to obtain a
/// `&dyn IpStackState`.
pub trait IpStackState {
    fn configured_ip_address(&self) -> Ipv4Addr;
    fn set_configured_ip_address(&self, addr: Ipv4Addr);
    fn configured_subnet_mask(&self) -> Ipv4Addr;
    fn set_configured_subnet_mask(&self, mask: Ipv4Addr);
    fn configured_default_gateway(&self) -> Ipv4Addr;
    fn set_configured_default_gateway(&self, gateway: Ipv4Addr);
    fn ip_assignment_method(&self) -> u8;
    fn set_ip_assignment_method(&self, method: u8);
    fn routing_multicast_address(&self) -> Ipv4Addr;
    fn set_routing_multicast_address(&self, addr: Ipv4Addr);
    fn ttl(&self) -> u8;
    fn set_ttl(&self, ttl: u8);
    fn friendly_name_len(&self) -> usize;
    fn friendly_name(&self) -> [u8; 30];
    fn set_friendly_name(&self, name: &[u8]);
    fn project_installation_id(&self) -> u16;
    fn set_project_installation_id(&self, id: u16);
}

/// Accessor returning a borrowed `dyn IpStackState`.
///
/// Implemented by every extension-state type that fronts a tunnelling
/// or non-tunnelling IP device — directly by
/// [`IpExtensionState`](crate::bcus::system_b::IpExtensionState) (which
/// returns itself) and indirectly by wrappers like
/// [`IpInterfaceExtension`](crate::bcus::system_b::IpInterfaceExtension)
/// (which return their inner IP state).
///
/// The dyn-typed return keeps the trait non-generic — generic code can
/// bound `ES: HasIpExtensionState` without threading `CAPS` through
/// every signature. Cost is one indirection per IP-config read, which
/// is acceptable on the cold paths (`DeviceInfoContext`,
/// `IpDiagnosticsContext`) that consume this.
pub trait HasIpExtensionState {
    /// Borrow the persisted IP extension state.
    fn ip_state(&self) -> &dyn IpStackState;
}

// ============================================================================
// Runtime IGMP-rebind plumbing
// ============================================================================

/// Access to a channel through which IP state mutators can request the
/// KNX/IP link-layer runtime to rejoin a new routing multicast group.
///
/// Implemented by [`IpExtensionState`](crate::bcus::system_b::IpExtensionState)
/// on the sender side and queried by the runtime's context impl to drain
/// on the receiver side. Living on a dedicated trait keeps the channel
/// out of [`IpStackState`]'s otherwise platform-agnostic API.
pub trait HasRoutingMulticastRebind {
    /// Access the rebind channel (capacity 2, `NoopRawMutex`).
    fn routing_multicast_rebind_channel(
        &self,
    ) -> &embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, Ipv4Addr, 2>;
}

/// Access to a set of additional KNX individual addresses assigned to
/// KNXnet/IP tunnelling slots.
///
/// Implemented by every IP extension state so the KNX/IP link-layer
/// context impl can be unconditional, but the default methods are
/// no-ops: only extensions that actually carry a tunnelling address
/// list (e.g. `IpInterfaceExtension`, which delegates to its
/// `TunnellingExtension`) override them. Plain `IpExtensionState`
/// without tunnelling adopts the defaults.
pub trait HasAdditionalIas {
    /// Write currently-assigned additional IAs into `buf`.
    ///
    /// Returns the number of addresses written (`<= buf.len()` and
    /// `<=` the populated count). Defaults to none.
    fn write_additional_ias_into(&self, _buf: &mut [IndividualAddress]) -> usize {
        0
    }

    /// Whether `addr` is currently assigned to a tunnelling slot.
    ///
    /// Called on the TPUART ACK hot path — keep it allocation-free.
    /// Defaults to `false`.
    fn additional_ia_is_assigned(&self, _addr: IndividualAddress) -> bool {
        false
    }
}

// ============================================================================
// Constants
// ============================================================================

/// KNX/IP System Setup multicast address: 224.0.23.12.
///
/// Per spec 03/02/06 §2.1 and 03/08/05 §2.3.2, this multicast group
/// is spec-fixed for discovery (`SEARCH_REQUEST`, 03/08/02 §4.2) and
/// IP System Broadcast frames (`ROUTING_SYSTEM_BROADCAST` = 0x0533,
/// 03/02/06 §4.1.3). A receiver must always listen on this address
/// regardless of how `PID_ROUTING_MULTICAST_ADDRESS` is configured —
/// §4.1.3 explicitly mandates that `ROUTING_SYSTEM_BROADCAST` frames
/// received on any other address are ignored, which matters because
/// `A_DomainAddressSerialNumber_Write` (the frame that reconfigures
/// routing) arrives on this group.
pub const SYSTEM_SETUP_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

/// Default initial value of `PID_ROUTING_MULTICAST_ADDRESS`.
///
/// Identical to [`SYSTEM_SETUP_MULTICAST_ADDRESS`] but semantically
/// distinct: the routing multicast is user-configurable via
/// `PID_ROUTING_MULTICAST_ADDRESS` (03/02/06 §1.5) whereas the
/// system-setup address is fixed. Keeping them as separate aliases
/// prevents a future repurposing of one from silently breaking the
/// spec invariants of the other.
pub const DEFAULT_MULTICAST_ADDR: Ipv4Addr = SYSTEM_SETUP_MULTICAST_ADDRESS;

/// Fixed KNX/IP UDP port per spec 03/02/06 §2.1.
///
/// Not configurable — the spec explicitly mandates 3671 for every
/// KNXnet/IP service family.
pub const KNX_PORT: u16 = 3671;

// ============================================================================
// Platform re-exports
// ============================================================================

/// Platform abstraction for querying current network state.
///
/// Implement this trait to provide platform-specific network information
/// (current IP address, MAC address, etc.) for KNX/IP devices.
pub use zweidraehte_platform::NetworkInfo as IpPlatform;

/// Platform abstraction for applying IP configuration changes.
///
/// On embedded platforms this reconfigures the network stack (e.g.,
/// switching between DHCP and static IP). On Linux this is a no-op.
pub use zweidraehte_platform::{IpConfig, NetworkConfig as IpPlatformConfig};
