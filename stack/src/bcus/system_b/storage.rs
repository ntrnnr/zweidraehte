//! Persistence infrastructure for System B devices.
//!
//! This module provides System B-specific persistence types
//! ([`PersistedState`], [`PersistedIpConfig`], [`LinkLayerConfig`],
//! [`LinkLayerState`]).
//!
//! The generic storage traits ([`DeviceStorage`](crate::storage::DeviceStorage),
//! [`NoStorage`](crate::storage::NoStorage)) live in [`crate::storage`].

use core::net::Ipv4Addr;

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};

use crate::{
    address::IndividualAddress,
    objects::tables::{
        Table,
        addr7::AddrTab7Impl,
        app::{Application, PeiApplication},
        asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
};

use crate::storage::DeviceIdentity;

// ============================================================================
// HasPersistedState — bridge between runtime and serializable state
// ============================================================================

/// Trait for converting between runtime state and its serializable form.
///
/// Implemented by [`SystemBDeviceState`](super::SystemBDeviceState) to
/// enable [`DeviceStorage`](crate::storage::DeviceStorage) backends to
/// work with the runtime state type directly, internalizing the
/// conversion to/from [`PersistedState`].
///
/// # Contract
///
/// - [`to_persisted`](Self::to_persisted) must capture all state that
///   survives a power cycle.
/// - [`from_persisted`](Self::from_persisted) must restore state such
///   that the device behaves identically to before the power cycle
///   (modulo volatile state like programming mode and run state).
pub trait HasPersistedState: Sized {
    /// The serializable snapshot type.
    type Persisted: Serialize + for<'de> Deserialize<'de>;

    /// Export current runtime state to a serializable snapshot.
    fn to_persisted(&self) -> Self::Persisted;

    /// Restore runtime state from a persisted snapshot and device identity.
    fn from_persisted(identity: &impl DeviceIdentity, persisted: Self::Persisted) -> Self;
}

// ============================================================================
// Link-layer config abstraction
// ============================================================================

/// Trait for link-layer-specific persistent configuration.
///
/// Different link layers may need to persist different configuration data.
/// TP1 devices use `()` (no link-layer config), while IP devices use
/// [`PersistedIpConfig`].
///
/// # Bounds
///
/// Implementations must be serializable for persistence and provide
/// factory defaults via `Default`.
pub trait LinkLayerConfig: Default + Serialize + for<'de> Deserialize<'de> {}

impl LinkLayerConfig for () {}

/// Runtime state for link-layer-specific persistent configuration.
///
/// This trait bridges the serializable config ([`LinkLayerConfig`]) and
/// the runtime representation with interior mutability (`Cell`/`RefCell`
/// fields). The runtime form allows `&self` mutation through the
/// `IpStackState` trait, while the config form is what gets serialized.
///
/// For IP devices, this is [`IpLinkLayerState`](super::IpLinkLayerState)
/// with `Cell<Ipv4Addr>`, `Cell<u8>`, etc.
/// For TP1 devices, this is `()`.
pub trait LinkLayerState: Sized {
    /// The serializable config type for this link-layer state.
    type Config: LinkLayerConfig;

    /// Create runtime state from a persisted config.
    fn from_config(config: Self::Config) -> Self;

    /// Export current runtime state to serializable config.
    fn to_config(&self) -> Self::Config;

    /// Reset to factory defaults.
    fn factory_reset(&self);
}

impl LinkLayerState for () {
    type Config = ();

    fn from_config(_config: ()) -> Self {}

    fn to_config(&self) {}

    fn factory_reset(&self) {
        // No link-layer state to reset.
    }
}

// ============================================================================
// Persisted state
// ============================================================================

/// All state that must survive power cycles.
///
/// This struct contains everything that ETS can configure and the device
/// must remember. It's serialized to storage when changes occur.
///
/// # Generic Parameters
///
/// The const generics are the actual byte sizes of each table:
/// - `ADT_SIZE`: Address table size (typically 2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size (typically 2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size (typically 2 + MAX_CO * 2)
/// - `P`: Application parameters type
/// - `L`: Link-layer-specific persistent config (e.g., [`PersistedIpConfig`]
///   for KNX/IP devices, `()` for TP1 devices)
///
/// Use [`table_sizes`] to calculate the const generics from max entry counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: Serialize",
    deserialize = "P: Deserialize<'de>",
))]
pub struct PersistedState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault = (),
    L: LinkLayerConfig = (),
> {
    /// Version of the persisted state format.
    ///
    /// Increment this when making breaking changes to allow migration.
    pub version: u8,

    /// Device individual address.
    pub individual_address: IndividualAddress,

    /// Authorization keys for levels 0-2.
    ///
    /// Level 3 has no key (it's the fallback when no key matches).
    /// Key value `[0xFF, 0xFF, 0xFF, 0xFF]` is the "default key".
    pub auth_keys: [[u8; 4]; 3],

    /// Routing count (hop count) for outgoing messages.
    pub routing_count: u8,

    /// Address table (TSAP → Group Address mapping).
    pub address_table: Table<AddrTab7Impl<ADT_SIZE>>,

    /// Association table (TSAP → ASAP mapping).
    pub association_table: Table<AssoTab6Impl<AST_SIZE>>,

    /// Group object table (CO type + flags).
    pub group_object_table: Table<CoTab7Impl<COT_SIZE>>,

    /// Application program data.
    pub application: Application<P>,

    /// PEI (Platform Extension Interface) program.
    pub pei_program: PeiApplication,

    /// Application program version (set by ETS during programming).
    pub program_version: [u8; 5],

    /// PEI program version (set by ETS during programming).
    pub pei_program_version: [u8; 5],

    /// Link-layer-specific persistent configuration.
    ///
    /// For KNX/IP devices this is [`PersistedIpConfig`] (friendly name,
    /// configured IP addresses, routing multicast, etc.).
    /// For TP1 devices this is `()`.
    ///
    /// The `serde(alias)` accepts the old field name `"ip_config"` for
    /// backwards compatibility with existing JSON state files.
    #[serde(alias = "ip_config")]
    pub link_layer_config: L,
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    L: LinkLayerConfig,
> PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P, L>
{
    /// Current version of the persisted state format.
    pub const VERSION: u8 = 1;

    /// Create a new persisted state with factory defaults.
    pub fn factory_default() -> Self {
        Self {
            version: Self::VERSION,
            individual_address: IndividualAddress::new(15, 15, 255),
            auth_keys: [[0xFF; 4]; 3], // All keys = default key
            routing_count: 6,          // Default per KNX spec
            address_table: Table::new(),
            association_table: Table::new(),
            group_object_table: Table::new(),
            application: Application::new(),
            pei_program: PeiApplication::new(),
            program_version: [0; 5],
            pei_program_version: [0; 5],
            link_layer_config: L::default(),
        }
    }
}

/// Calculate table sizes from max entry counts.
///
/// Returns `(adt_size, ast_size, cot_size)` for use as const generics.
///
/// # Example
///
/// ```rust,ignore
/// const SIZES: (usize, usize, usize) = table_sizes(64, 64, 32);
/// type MyPersistedState = PersistedState<{ SIZES.0 }, { SIZES.1 }, { SIZES.2 }, ()>;
/// ```
pub const fn table_sizes(max_addr: usize, max_asso: usize, max_co: usize) -> (usize, usize, usize) {
    (
        2 + max_addr * 2, // ADT: 2-byte count + 2 bytes per entry
        2 + max_asso * 4, // AST: 2-byte count + 4 bytes per entry
        2 + max_co * 2,   // COT: 2-byte count + 2 bytes per entry
    )
}

// ============================================================================
// IP-specific persistent config
// ============================================================================

/// Persisted IP configuration (for KNX/IP devices).
///
/// All IP-specific settings that can be configured via ETS or
/// the IP Parameter Object. Implements [`LinkLayerConfig`] so it
/// can be used as the `L` parameter of [`PersistedState`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIpConfig {
    /// Friendly name for discovery (up to 30 bytes).
    pub friendly_name: [u8; 30],

    /// Length of the friendly name.
    pub friendly_name_len: u8,

    /// Configured (static) IP address.
    pub configured_ip: [u8; 4],

    /// Configured subnet mask.
    pub configured_subnet: [u8; 4],

    /// Configured default gateway.
    pub configured_gateway: [u8; 4],

    /// IP assignment method (bitfield: Manual=1, BootP=2, DHCP=4, AutoIP=8).
    pub ip_assignment_method: u8,

    /// Routing multicast address.
    pub routing_multicast: [u8; 4],

    /// Multicast TTL value.
    pub ttl: u8,

    /// Project installation ID.
    pub project_installation_id: u16,
}

impl Default for PersistedIpConfig {
    fn default() -> Self {
        Self {
            friendly_name: [0; 30],
            friendly_name_len: 0,
            configured_ip: [0, 0, 0, 0],
            configured_subnet: [255, 255, 255, 0],
            configured_gateway: [0, 0, 0, 0],
            ip_assignment_method: 0x04, // DHCP
            routing_multicast: [224, 0, 23, 12],
            ttl: 16,
            project_installation_id: 0,
        }
    }
}

impl LinkLayerConfig for PersistedIpConfig {}

impl PersistedIpConfig {
    /// Get the configured IP address as an Ipv4Addr.
    pub fn configured_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.configured_ip)
    }

    /// Get the routing multicast address as an Ipv4Addr.
    pub fn routing_multicast_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.routing_multicast)
    }
}

