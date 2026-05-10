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

// ============================================================================
// IP Secure context traits — shape only, used once the crypto layer lands
// ============================================================================
//
// These three traits map the spec-required IP Secure runtime surface
// (Vol 3 Part 8 §9, doc `03_08_09 KNX IP Secure v01.01.02 AS.pdf`)
// into the link-layer context vocabulary:
//
// - [`HasIpSecureConfig`]  — persistent per-device secrets (PIDs 91–97
//                            of the KNXnet/IP Parameter Object). All
//                            getters return live state because every
//                            property is writable via secure
//                            `A_PropertyValue_Write` at runtime.
// - [`HasMcTimer`]         — the 48-bit free-running multicast timer
//                            (§2.2.2.2.2) plus the `mc_timer_authentic`
//                            flag that gates multicast payload
//                            forwarding (§2.2.2.3.2.8).
// - [`HasIpSecureSessions`] — per-session runtime state pool. Sized
//                             from `KnxNetIpDefinition::MAX_SECURE_SESSIONS`,
//                             TCP-only per §2.2.3.3.
//
// None of them are added to the [`KnxNetIpContext`](super::KnxNetIpContext)
// supertrait alias yet — that bundle is what every existing call site
// already implements. Adding the IP-Secure traits unconditionally
// would force every non-secure device to write empty stubs. Instead,
// the eventual crypto landing will introduce a parallel
// [`KnxNetIpSecureContext`] supertrait combining `KnxNetIpContext`
// with these three; secure-only code paths bound on the combo, plain
// paths stay on `KnxNetIpContext`.

/// Per-device persistent IP-Secure secret material (PIDs 91–97 of the
/// KNXnet/IP Parameter Object).
pub trait HasIpSecureConfig {
    /// PID 91 — Secure Backbone Key (16 B). AES-128 key for all
    /// multicast SECURE_WRAPPER / TIMER_NOTIFY MAC + encryption.
    /// Writing this resets `mc_timer` to 0 (§2.2.2.2.2).
    fn backbone_key(&self) -> &[u8; 16];

    /// PID 92 — Device Authentication Code (16 B). CCM key for the
    /// SESSION_RESPONSE MAC (§2.3.1.3). Factory-default value is the
    /// device's FDSK.
    fn device_authentication_code(&self) -> &[u8; 16];

    /// PID 93 — Password Hashes, indexed by User ID (1..=127).
    /// `password_hash(1)` is the management user; `2..=127` are device-
    /// specific roles. CCM key for `SESSION_AUTHENTICATE` MAC
    /// (§2.3.1.4). Returns `None` for unprogrammed slots.
    fn password_hash(&self, user_id: u8) -> Option<&[u8; 16]>;

    /// PID 94 — Per-service-family security version. A non-zero value
    /// means the family requires SECURE_WRAPPER; zero means plain
    /// frames are accepted (§2.3.1.5).
    fn secured_service_family(&self, fam: zweidraehte_proto::messages::knxip::substructs::ServiceFamily) -> u8;

    /// PID 95 — Multicast latency tolerance in ms. Replay-window for
    /// multicast `SECURE_WRAPPER`. Default 2000 ms (§2.3.1.6).
    fn multicast_latency_tolerance(&self) -> u32;

    /// PID 96 — Sync latency fraction (PDT_SCALING). Drives
    /// `syncLatencyTolerance` in the TIMER_NOTIFY state machine
    /// (§2.2.2.3.2.2). Default 10.2 % (`0x1A`).
    fn sync_latency_fraction(&self) -> u8;

    /// PID 97 — Tunnelling Users table. Returns the tunnelling-address
    /// indices the given user ID is authorised for. User ID `1` is
    /// implicit (mgmt user has access to all) and is **not** stored
    /// in this table (§2.3.1.8).
    fn tunnelling_user(&self, user_id: u8) -> impl Iterator<Item = u8>;
}

/// The 48-bit free-running multicast timer plus the
/// `mc_timer_authentic` gate.
///
/// **NV-persistence (§2.2.4.2):** implementations must persist
/// `mc_timer` to non-volatile storage at intervals ≤ 1 hour
/// **measured in mc_timer time, not wall-clock**. On power-up, read
/// the persisted T then act as if T+D had been used (where D is the
/// persistence interval) before re-using.
///
/// **Reset semantics (§2.2.2.2.2):** writing `backbone_key` resets
/// `mc_timer` to 0 and clears `mc_timer_authentic`.
pub trait HasMcTimer {
    /// Current 48-bit multicast timer value (only the low 48 bits are
    /// used; `u64` is the convenient width for arithmetic).
    fn mc_timer(&self) -> u64;

    /// Update the multicast timer. May trigger an NV flush per the
    /// persistence-interval rule.
    fn set_mc_timer(&self, value: u64);

    /// True once the first authentic `TIMER_NOTIFY` echo of our own
    /// `(serial, tag)` round-trip has arrived (§2.2.2.3.2.8). While
    /// false, multicast `SECURE_WRAPPER` payload must **not** be
    /// forwarded to upper layers — roughly 17 s after power-up on a
    /// typical Ethernet LAN.
    fn mc_timer_authentic(&self) -> bool;

    /// Set the `mc_timer_authentic` flag. Set to `true` on first
    /// authenticated echo; reset to `false` on power-up and when
    /// `backbone_key` changes.
    fn set_mc_timer_authentic(&self, value: bool);
}

/// Per-session runtime state pool for unicast IP Secure sessions.
///
/// IP Secure unicast sessions are TCP-only (§2.2.3.3), so the pool is
/// naturally sized at
/// [`KnxNetIpDefinition::MAX_SECURE_SESSIONS`](super::definition::KnxNetIpDefinition::MAX_SECURE_SESSIONS),
/// which defaults to `MAX_TCP_STREAMS`. Sessions are allocated on
/// `SESSION_REQUEST`, freed on `STATUS_CLOSE` / timeout / TCP close.
pub trait HasIpSecureSessions {
    /// Allocate a fresh session slot and return a mutable handle.
    /// Returns `None` if the pool is exhausted (server replies with
    /// `STATUS_RESERVED` per §2.2.3.7.6).
    fn allocate_session(&mut self) -> Option<&mut super::secure::IpSecureSessionSlot>;

    /// Look up an active session by its server-assigned ID.
    fn session_by_id(&mut self, session_id: u16) -> Option<&mut super::secure::IpSecureSessionSlot>;

    /// Free a session slot. Called on `STATUS_CLOSE`, `STATUS_TIMEOUT`,
    /// `STATUS_AUTHENTICATION_FAILED`, or when the underlying TCP
    /// connection closes (§2.4.2 — all sessions on a closing TCP
    /// connection are released implicitly).
    fn release_session(&mut self, session_id: u16);
}

/// Supertrait alias bundling everything the IP Secure dispatch path
/// will need on top of [`KnxNetIpContext`](super::KnxNetIpContext).
/// Currently has no impls — used by the eventual SECURE_WRAPPER /
/// SESSION_* dispatch arms.
pub(crate) trait KnxNetIpSecureContext:
    super::KnxNetIpContext + HasIpSecureConfig + HasMcTimer + HasIpSecureSessions
{
}

impl<T> KnxNetIpSecureContext for T where
    T: super::KnxNetIpContext + HasIpSecureConfig + HasMcTimer + HasIpSecureSessions
{
}
