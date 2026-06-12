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
/// `IpStateView` has exactly one impl and never carries delegation.
///
/// Generic context code that needs to read IP config bounds
/// `ES: HasIpExtensionState` and calls `.ip_state()` to obtain a
/// `&dyn IpStateView`.
pub trait IpStateView {
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

/// Accessor returning a borrowed `dyn IpStateView`.
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
    fn ip_state(&self) -> &dyn IpStateView;
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
/// out of [`IpStateView`]'s otherwise platform-agnostic API.
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
// KNX IP Secure configuration view
// ============================================================================

/// Configuration events the secure-routing timer sync must react to,
/// pushed from the property write handlers (AL task) to the KNX/IP
/// link-layer runtime through [`IpSecureStateView::mc_sync_event_channel`].
#[derive(Debug, Clone, Copy)]
pub enum IpSecureSyncEvent {
    /// PID 91 was written with a *different* key — event E11 of the
    /// timer sync state machine (03/08/09 §2.2.2.3.2.5): the mc_timer
    /// implicitly resets to 0 and the synchronization restarts.
    /// Rewriting the identical key (spec event E12) does not fire this.
    BackboneKeyChanged,
    /// The required security version for the Routing service family
    /// (PID 94) changed. Timer synchronization "shall only be active if
    /// at least one service family using multicast communication is set
    /// to require secure communication" (§2.2.2.3.2.8) — the runtime
    /// starts or stops the sync accordingly.
    RoutingConfigChanged,
}

/// Read access to the persisted KNX IP Secure secret material (PIDs
/// 91–97 of the KNXnet/IP Parameter Object, 03/08/09 §2.3.1).
///
/// Key material is returned **by value** — the storage uses interior
/// mutability (`Cell`/`RefCell`), so borrows could not escape the
/// accessor anyway, and 16 bytes copy for free.
pub trait IpSecureStateView {
    /// PID 91 — Secure Backbone Key. AES-128 key for multicast
    /// SECURE_WRAPPER / TIMER_NOTIFY (secure routing). All-zero means
    /// "not provisioned".
    fn backbone_key(&self) -> [u8; 16];

    /// PID 92 — Device Authentication Code: CCM key for the
    /// SESSION_RESPONSE MAC (§2.3.1.3). Factory default is the FDSK.
    fn device_authentication_code(&self) -> [u8; 16];

    /// PID 93 — password hash for `user_id` (1 = management user,
    /// 2..=127 device-specific). `None` for unprogrammed slots
    /// (§2.3.1.4).
    fn password_hash(&self, user_id: u8) -> Option<[u8; 16]>;

    /// PID 94 — required security version for a service family. Zero
    /// means plain frames are accepted; non-zero means the family only
    /// accepts SECURE_WRAPPER traffic (§2.3.1.5).
    fn secured_service_family(&self, family: zweidraehte_proto::messages::knxip::substructs::ServiceFamily) -> u8;

    /// PID 95 — multicast latency tolerance in ms (replay window for
    /// multicast SECURE_WRAPPER; default 2000, §2.3.1.6).
    fn multicast_latency_tolerance_ms(&self) -> u16;

    /// PID 96 — sync latency fraction (PDT_SCALING, default 0x1A ≙
    /// 10.2 %, §2.3.1.7).
    fn sync_latency_fraction(&self) -> u8;

    /// PID 97 — whether `user_id` is authorised for the tunnelling
    /// slot with the given 1-based tunnelling-address index. The
    /// management user (1) is implicitly authorised for every slot and
    /// never stored in the table (§2.3.1.8).
    fn tunnelling_user_allowed(&self, user_id: u8, tunnelling_slot: u8) -> bool;

    /// Persisted multicast-timer watermark (§2.2.4.2): the highest
    /// mc_timer value guaranteed not to have been exceeded by any
    /// frame this device sent. 0 means "never persisted with the
    /// current backbone key" — on power-up such a device starts at
    /// mc_timer = 0 instead of watermark + interval.
    fn persisted_mc_timer(&self) -> u64;

    /// Advance the persisted multicast-timer watermark. Called by the
    /// link-layer runtime before it sends (and after it adopts) timer
    /// values beyond the previous watermark, so the timer can never
    /// run backwards across a power loss (§2.2.4.2).
    fn set_persisted_mc_timer(&self, value: u64);

    /// Channel through which the property write handlers notify the
    /// link-layer runtime of secure-routing config changes (backbone
    /// key rewrite, Routing security version flip). Mirrors the
    /// [`HasRoutingMulticastRebind`] plumbing pattern.
    fn mc_sync_event_channel(
        &self,
    ) -> &embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, IpSecureSyncEvent, 2>;
}

/// Capability gate for KNX IP Secure on the extension state.
///
/// Same shape as [`HasAdditionalIas`]: every IP extension state
/// implements it (the default returns `None`), and only the secure
/// extension overrides it to expose its [`IpSecureStateView`]. The
/// KNX/IP link-layer context impl can therefore be written once with an
/// `ES: HasIpSecureView` bound without forcing non-secure devices to
/// carry secret storage.
pub trait HasIpSecureView {
    /// Borrow the IP Secure configuration, if this extension carries it.
    fn ip_secure_view(&self) -> Option<&dyn IpSecureStateView> {
        None
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
