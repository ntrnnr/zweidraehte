#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]
#![feature(associated_type_defaults)]

// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;

mod fmt;

#[macro_use]
mod macros;

pub mod access_policy;
pub mod address;
pub mod bcus;
pub mod config;
pub mod context;
pub mod dpt;
pub mod encoding;
pub mod error;
pub mod ets;
pub mod layers;
pub mod memory;
pub mod messages;
pub mod objects;
pub mod prelude;
pub mod restart;
pub mod router;
pub mod storage;
pub mod util;

use core::{
    cell::{Cell, RefCell},
    mem::MaybeUninit,
};

use const_default::ConstDefault;
use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    channel::{Channel, DynamicReceiver, DynamicSender},
    pubsub::{PubSubBehavior, PubSubChannel},
};
use embassy_time::{Duration, TimeoutError, with_timeout};
use messages::knx::KnxMessageBuffer;

use crate::{
    address::IndividualAddress,
    context::BufferManagerContext,
    layers::{
        ActorRequest, LinkLayerBuilder, LinkLayerBuilderBase, Request,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        transport::{TlStyle, TransportLayer},
    },
    memory::MemoryMap,
    messages::buffers::{Buffer, BufferManager, DynBufferManager},
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects, LifecycleEvent},
        interface::{HasDeviceObject, HasRoutingCount, PropertyServiceHandler},
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasRunStateMachine,
        },
    },
};

/// Error type for read object operations with timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReadObjectError {
    /// The read request timed out without receiving a response
    Timeout,
    /// The object is busy (already transmitting)
    Busy,
}

/// Error type for update/write object operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UpdateObjectError {
    /// The object is busy (already transmitting)
    Busy,
}

/// Trait for stack state types.
///
/// Stack state holds runtime configuration that can be shared between
/// the stack, layers, and interface objects (e.g., programming mode, individual address).
/// This state can later be persisted to flash/storage.
///
/// # Example
///
/// ```rust,ignore
/// use core::cell::RefCell;
/// use zweidraehte::{StackState, address::IndividualAddress};
///
/// pub struct MyDeviceState {
///     individual_address: RefCell<IndividualAddress>,
/// }
///
/// impl Default for MyDeviceState {
///     fn default() -> Self {
///         Self {
///             individual_address: RefCell::new(IndividualAddress::new(1, 0, 1)),
///         }
///     }
/// }
///
/// impl StackState for MyDeviceState {
///     fn individual_address(&self) -> IndividualAddress {
///         *self.individual_address.borrow()
///     }
///
///     fn set_individual_address(&self, addr: IndividualAddress) {
///         *self.individual_address.borrow_mut() = addr;
///     }
///
///     fn serial_number(&self) -> &[u8; 6] {
///         &[0x00, 0xFA, 0x00, 0x00, 0x00, 0x00]
///     }
/// }
/// ```
pub trait StackState {
    /// Get the device's individual address.
    ///
    /// This is the unique address assigned to this device on the KNX bus.
    /// It is used as the source address for outgoing messages.
    fn individual_address(&self) -> IndividualAddress;

    /// Set the device's individual address.
    ///
    /// This is typically set during device configuration or via
    /// `A_IndividualAddress_Write` when in programming mode.
    fn set_individual_address(&self, addr: IndividualAddress);

    /// Get the device serial number (6 bytes).
    ///
    /// The serial number consists of 2 bytes manufacturer ID followed by
    /// 4 bytes device-specific identifier. Used for `A_IndividualAddressSerialNumber_Read/Write`.
    fn serial_number(&self) -> &[u8; 6];

    /// Get the runtime maximum APDU length.
    ///
    /// This value is reported via PID 56 (MAX_APDU_LENGTH) in the Device Object.
    /// It represents the actual limit based on detected hardware capabilities:
    ///
    /// - USB interface maximum frame size
    /// - TP1 MAC type (standard vs Extended Frame Format)
    /// - Other link layer constraints
    ///
    /// **Important**: This value must be ≤ [`StackDefinition::MAX_APDU_LENGTH`],
    /// which determines the compile-time buffer allocation.
    ///
    /// Common values:
    /// - 14: Standard TP1 without Extended Frame Format
    /// - 255: TP1 with EFF or KNX/IP
    ///
    /// Default implementation returns 254 (full EFF/KNX/IP support).
    /// Override this in your state implementation to return a value based on
    /// detected hardware capabilities.
    fn max_apdu_length(&self) -> u16 {
        crate::config::MAX_APDU_LENGTH_EXTENDED
    }

    /// Set the runtime maximum APDU length.
    ///
    /// This is called by the link layer after detecting hardware capabilities.
    /// For example, a TP1 link layer may detect that the interface doesn't
    /// support Extended Frame Format and set this to 14 bytes.
    ///
    /// The value should not exceed [`StackDefinition::MAX_APDU_LENGTH`] which
    /// determines the compile-time buffer allocation.
    ///
    /// Default implementation does nothing (for state implementations that
    /// don't support runtime APDU length changes).
    fn set_max_apdu_length(&self, _length: u16) {
        // Default: no-op for implementations that don't support this
    }

    // =========================================================================
    // Programming Mode
    // =========================================================================

    /// Check if the device is in programming mode.
    ///
    /// Programming mode is a volatile runtime flag — it does not survive
    /// restarts and is not persisted. When set, the device responds to
    /// `A_IndividualAddress_Read` and accepts `A_IndividualAddress_Write`.
    ///
    /// Default implementation returns `false`.
    fn is_programming_mode(&self) -> bool {
        false
    }

    /// Set the programming mode flag.
    ///
    /// Default implementation does nothing.
    fn set_programming_mode(&self, _enabled: bool) {}

    // =========================================================================
    // Persistence
    // =========================================================================

    /// Mark the device state as dirty (needing persistence).
    ///
    /// Called by the stack whenever persistent state is modified through
    /// property writes, memory writes, or other management operations.
    /// Implementations that support persistence should set a dirty flag
    /// so that state can be saved at the appropriate time (e.g., before
    /// a restart or periodically).
    ///
    /// Default implementation does nothing (for state implementations
    /// without persistence).
    fn mark_dirty(&self) {
        // Default: no-op for implementations without persistence
    }

    // =========================================================================
    // Authorization (A_Authorize_Request / A_Key_Write)
    // =========================================================================

    /// Get the maximum number of access levels supported.
    ///
    /// Returns 4 for levels 0-3, or 16 for levels 0-15.
    /// Default is 4 (levels 0-3).
    fn max_access_levels(&self) -> u8 {
        4
    }

    /// Get the default access level for new connections.
    ///
    /// This is the access level granted when a connection is opened without
    /// explicit authorization. It corresponds to the first level that has
    /// the default key (`0xFFFFFFFF`).
    ///
    /// For a device with `keys[0]`=0x00, `keys[1]`=0x12345678, `keys[2]`=0xFF..FF, `keys[3]`=0xFF..FF,
    /// this would return 2 (the first match for 0xFFFFFFFF when walking from level 0 upward).
    ///
    /// Default implementation: returns level 3 (minimum access, "access for everyone").
    /// Implementations with a key table should override this to call `authorize(&[0xFF, 0xFF, 0xFF, 0xFF])`.
    fn default_access_level(&self) -> u8 {
        self.max_access_levels() - 1 // Level 3 = minimum access = "access for everyone"
    }

    /// Authorize with a 4-byte key and return the associated access level.
    ///
    /// Returns the access level (0-3 or 0-15) associated with the key:
    /// - If key matches a configured key: return the associated level (first match wins, walking from level 0)
    /// - If key is not found in table: return max level (3 or 15, minimum access)
    ///
    /// Note: The key `0xFFFFFFFF` is NOT special - it must be found in the key table
    /// like any other key. This allows devices to configure which level(s) use the default key.
    ///
    /// Default implementation: returns minimum access for all keys (no key table).
    fn authorize(&self, _key: &[u8; 4]) -> u8 {
        self.max_access_levels() - 1 // No key table -> minimum access
    }

    /// Write a new key for a specific access level.
    ///
    /// Arguments:
    /// - `level`: The access level to set the key for
    /// - `key`: The new 4-byte key
    /// - `ctx`: The access context of the current connection
    ///
    /// Returns the level if successful, or 0xFF if:
    /// - The level is invalid (>= max_access_levels)
    /// - The caller's access level is higher (less privileged) than the target level
    ///
    /// If key is `0xFFFFFFFF`, the key for that level is deleted (set to invalid).
    ///
    /// Default implementation: always returns 0xFF (not supported).
    fn key_write(&self, _level: u8, _key: &[u8; 4], _ctx: AccessContext) -> u8 {
        0xFF // Not supported by default
    }
}

/// Number of authorization access levels supported (0-3).
pub const MAX_ACCESS_LEVELS: usize = 4;

/// Number of settable authorization keys (levels 0-2).
/// Level 3 is "access for everyone" and has no key - it's what you get when auth fails.
pub const NUM_AUTH_KEYS: usize = 3;

// ============================================================================
// Access Context
// ============================================================================

/// Authorization context for a service request.
///
/// Bundles all access-related state needed to evaluate policies.
/// Currently contains only the legacy 4-level access level.
/// Will be extended for KNX Secure with security mode, role, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccessContext {
    /// Legacy access level (0 = max access, 3 = min access).
    pub access_level: u8,
    // Future KNX Secure fields:
    // pub security_mode: bool,
    // pub security_ctrl: SecurityControl,
}

impl AccessContext {
    /// Create a new access context with the given legacy access level.
    pub const fn new(access_level: u8) -> Self {
        Self { access_level }
    }

    /// Check whether this context has at least the given access level.
    ///
    /// In KNX, lower number = more access. Returns true if
    /// `self.access_level <= required`.
    pub const fn has_level(&self, required: u8) -> bool {
        self.access_level <= required
    }

    /// Minimum-access context (level 3, no special privileges).
    pub const MIN_ACCESS: Self = Self { access_level: 3 };

    /// Maximum-access context (level 0, full system access).
    pub const MAX_ACCESS: Self = Self { access_level: 0 };
}

// ============================================================================
// Access Source
// ============================================================================

/// Describes where to look up the access level for a message.
///
/// Messages flowing through the stack carry this tag so the application layer
/// knows how to resolve the effective [`AccessContext`]:
///
/// - **Connectionless** messages (broadcast, group, individual-unaddressed)
///   use the default access level from [`StackState::default_access_level()`].
/// - **Connection-oriented** messages reference a slot in the shared
///   [`ConnectionAuthLevels`] where the transport layer maintains the
///   current authorization level per connection.
/// - **Explicit** is for special paths (e.g. KNX/IP Device Management) that
///   bypass the transport layer and need to stamp a fixed access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AccessSource {
    /// Connectionless — use the default access level.
    Default,
    /// Connection-oriented — look up from shared store by slot index.
    Connection(u8),
    /// Explicit access context (e.g. KNX/IP device management).
    Explicit(AccessContext),
}

// ============================================================================
// Connection Access Store
// ============================================================================

/// Per-connection access level store.
///
/// Sized by the total number of transport-layer connections
/// (`TL_MAX_INCOMING + TL_MAX_OUTGOING`) and owned by the device state type.
/// The transport and application layers access it through the
/// [`HasConnectionAuth`] trait, which hides the const generic `N`.
///
/// The slot index matches the connection table: slot 0 is the first incoming
/// connection, etc.  On connect the TL resets the slot to the default level;
/// on authorize the AL writes the granted level directly.
///
/// Single-threaded (embassy `NoopRawMutex`), so [`Cell`] is safe.
pub struct ConnectionAuthLevels<const N: usize> {
    levels: [Cell<AccessContext>; N],
}

impl<const N: usize> ConnectionAuthLevels<N> {
    pub const fn new() -> Self {
        Self { levels: [const { Cell::new(AccessContext::MIN_ACCESS) }; N] }
    }

    /// Read the access context for a connection slot.
    pub fn get(&self, slot: u8) -> AccessContext {
        self.levels[slot as usize].get()
    }

    /// Write the access context for a connection slot.
    pub fn set(&self, slot: u8, ctx: AccessContext) {
        self.levels[slot as usize].set(ctx);
    }

    /// Reset a slot back to the given default level.
    pub fn reset(&self, slot: u8, default_level: u8) {
        self.levels[slot as usize].set(AccessContext::new(default_level));
    }
}

impl<const N: usize> Default for ConnectionAuthLevels<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for state types that contain a [`ConnectionAuthLevels`].
///
/// Provides slot-level access to per-connection authorization levels.
/// The const generic `N` on [`ConnectionAuthLevels`] is hidden behind
/// these methods so that layers don't need to carry the generic.
///
/// The transport layer resets slot levels on connect/disconnect; the
/// application layer reads and writes them on authorize and access checks.
pub trait HasConnectionAuth {
    /// Read the access context for a connection slot.
    fn connection_access(&self, slot: u8) -> AccessContext;

    /// Write the access context for a connection slot.
    fn set_connection_access(&self, slot: u8, ctx: AccessContext);

    /// Reset a slot back to the given default level.
    fn reset_connection_access(&self, slot: u8, default_level: u8);
}

// ============================================================================
// IP Stack State Extension
// ============================================================================

use core::net::Ipv4Addr;

/// Extended stack state for KNXnet/IP devices.
///
/// This trait extends [`StackState`] with IP-specific configuration and
/// platform queries needed by [`IpParameterObject`](crate::objects::interface::IpParameterObject).
///
/// The trait separates:
/// - **Current values** (read from platform/OS): `current_ip_address()`, `current_subnet_mask()`, etc.
/// - **Configured values** (ETS-programmable, persisted): `configured_ip_address()`, etc.
///
/// # Example
///
/// ```rust,ignore
/// use core::cell::RefCell;
/// use core::net::Ipv4Addr;
/// use zweidraehte::{StackState, IpStackState, address::IndividualAddress};
///
/// pub struct MyIpDeviceState {
///     // Base state
///     individual_address: RefCell<IndividualAddress>,
///     // IP state
///     configured_ip: RefCell<Ipv4Addr>,
///     configured_subnet: RefCell<Ipv4Addr>,
///     configured_gateway: RefCell<Ipv4Addr>,
///     friendly_name: RefCell<[u8; 30]>,
///     // Platform reference for current values
///     // ...
/// }
/// ```
pub trait IpStackState {
    // ========================================================================
    // Current values (read from platform/OS - typically read-only)
    // ========================================================================

    /// Get the current IP address from the platform/OS.
    ///
    /// This reflects the actual IP address the device is using, which may
    /// differ from the configured address if using DHCP.
    fn current_ip_address(&self) -> Ipv4Addr;

    /// Get the current subnet mask from the platform/OS.
    fn current_subnet_mask(&self) -> Ipv4Addr;

    /// Get the current default gateway from the platform/OS.
    fn current_default_gateway(&self) -> Ipv4Addr;

    /// Get the MAC address of the network interface.
    fn mac_address(&self) -> [u8; 6];

    // ========================================================================
    // Configured values (ETS-programmable, persisted)
    // ========================================================================

    /// Get the configured (static) IP address.
    ///
    /// This is the address configured via ETS, used when IP assignment
    /// method is set to manual/static.
    fn configured_ip_address(&self) -> Ipv4Addr;

    /// Set the configured IP address.
    fn set_configured_ip_address(&self, addr: Ipv4Addr);

    /// Get the configured subnet mask.
    fn configured_subnet_mask(&self) -> Ipv4Addr;

    /// Set the configured subnet mask.
    fn set_configured_subnet_mask(&self, mask: Ipv4Addr);

    /// Get the configured default gateway.
    fn configured_default_gateway(&self) -> Ipv4Addr;

    /// Set the configured default gateway.
    fn set_configured_default_gateway(&self, gateway: Ipv4Addr);

    /// Get the IP assignment method.
    ///
    /// - Bit 0: Manual (static IP)
    /// - Bit 1: BootP
    /// - Bit 2: DHCP
    /// - Bit 3: AutoIP
    fn ip_assignment_method(&self) -> u8;

    /// Set the IP assignment method.
    fn set_ip_assignment_method(&self, method: u8);

    /// Get the current IP assignment method in use.
    fn current_ip_assignment_method(&self) -> u8;

    /// Get IP capabilities supported by this device.
    ///
    /// Bitfield indicating which assignment methods are supported.
    fn ip_capabilities(&self) -> u8;

    /// Get the routing multicast address.
    ///
    /// Default is 224.0.23.12 (KNX multicast address).
    fn routing_multicast_address(&self) -> Ipv4Addr;

    /// Set the routing multicast address.
    fn set_routing_multicast_address(&self, addr: Ipv4Addr);

    /// Get the multicast TTL value.
    ///
    /// Default is 16 per KNX specification.
    fn ttl(&self) -> u8;

    /// Set the multicast TTL value.
    fn set_ttl(&self, ttl: u8);

    /// Get the friendly name length.
    fn friendly_name_len(&self) -> usize;

    /// Copy the friendly name into the provided buffer.
    ///
    /// Returns the number of bytes copied.
    fn friendly_name(&self, buf: &mut [u8]) -> usize;

    /// Set the friendly name.
    fn set_friendly_name(&self, name: &[u8]);

    /// Get the KNXnet/IP device capabilities.
    ///
    /// Bit 0: Device Management
    /// Bit 1: Tunneling
    /// Bit 2: Routing
    /// Bit 3: Remote Logging
    /// Bit 4: Remote Configuration & Diagnosis
    /// Bit 5: Object Server
    fn knxnetip_device_capabilities(&self) -> u16;

    /// Get the project installation ID.
    ///
    /// 2 bytes: project number (bits 15-4) + installation number (bits 3-0)
    fn project_installation_id(&self) -> u16;

    /// Set the project installation ID.
    fn set_project_installation_id(&self, id: u16);

    /// Maximum number of additional individual addresses this device supports.
    ///
    /// Returns 0 for devices that don't support tunneling. Used by property
    /// descriptors to report the array capacity.
    fn additional_individual_address_capacity(&self) -> usize {
        0
    }

    /// Write additional individual addresses into `buf`.
    ///
    /// Returns the number of addresses written (`<= buf.len()`).
    fn write_additional_individual_addresses(&self, _buf: &mut [IndividualAddress]) -> usize {
        0
    }

    /// Replace additional individual addresses.
    fn set_additional_individual_addresses(&self, _addresses: &[IndividualAddress]) -> Result<(), ()> {
        Err(())
    }
}

/// Default KNX multicast address: 224.0.23.12
pub const DEFAULT_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

/// Default KNX/IP port
pub const KNX_PORT: u16 = 3671;

/// Platform abstraction for querying current network state.
///
/// Implement this trait to provide platform-specific network information
/// (current IP address, MAC address, etc.) for KNX/IP devices.
pub use platform::NetworkInfo as IpPlatform;

/// Platform abstraction for applying IP configuration changes.
///
/// On embedded platforms this reconfigures the network stack (e.g.,
/// switching between DHCP and static IP). On Linux this is a no-op.
pub use platform::{IpConfig, NetworkConfig as IpPlatformConfig};

/// Convenience trait alias for types that implement both [`StackState`] and
/// [`IpStackState`].
///
/// This exists because `define_interface_object!` only accepts a single
/// trait bound, so [`IpParameterObject`](crate::objects::interface::IpParameterObject) uses `S: IpDevice` instead of
/// `S: StackState + IpStackState`.
pub trait IpDevice: StackState + IpStackState {}
impl<T: StackState + IpStackState> IpDevice for T {}

pub trait StackDefinition: Copy {
    /// Device descriptor containing all device identification and configuration.
    ///
    /// This is the **single source of truth** for device identity including:
    /// - Hardware identification (mask version, manufacturer ID, serial number, hardware type)
    /// - Application program info (app ID, version)
    /// - Table capacities (max addresses, associations, communication objects)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use zweidraehte::ets::DeviceDescriptor;
    ///
    /// const MY_DEVICE: DeviceDescriptor = DeviceDescriptor {
    ///     mask_version: MaskVersion::SystemBTp1,
    ///     manufacturer_id: 0x00FA,
    ///     hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    ///     application_id: 0xF023,
    ///     application_version: 0x01,
    ///     max_address_table_entries: 64,
    ///     max_association_table_entries: 64,
    ///     max_com_objects: 32,
    ///     pei_type: 0,
    /// };
    ///
    /// impl StackDefinition for MyDevice {
    ///     const DEVICE: &'static DeviceDescriptor = &MY_DEVICE;
    ///     // ... other fields
    /// }
    /// ```
    ///
    /// # Note on Serial Number
    ///
    /// The serial number is NOT part of the device descriptor because it's unique
    /// per physical device instance (factory-programmed). Serial number should be
    /// stored in runtime state and read from persistent storage or hardware.
    const DEVICE: &'static ets::DeviceDescriptor;

    /// Maximum APDU length for compile-time buffer allocation.
    ///
    /// This is the APDU payload size (not the full buffer size). The actual buffer
    /// size is calculated by [`config::buffer_size_for_apdu()`] which adds:
    /// - Frame overhead (6 bytes): ctrl + src + dst + npdu
    /// - Headroom (16 bytes): for cEMI expansion + KNXnet/IP headers
    ///
    /// For the actual runtime limit (which can be lower based on detected hardware),
    /// see [`StackState::max_apdu_length()`]. The runtime limit is what gets
    /// reported via PID 56 (MAX_APDU_LENGTH) in the Device Object.
    ///
    /// Common values:
    /// - [`config::MAX_APDU_LENGTH_TP1_STANDARD`] (14): Standard TP1 without EFF
    /// - [`config::MAX_APDU_LENGTH_EXTENDED`] (255): TP1 with EFF or KNX/IP
    ///
    /// Default is 255 (full support for extended frames).
    const MAX_APDU_LENGTH: u16 = config::MAX_APDU_LENGTH_EXTENDED;

    /// Device descriptor type 2 (14 bytes, optional).
    ///
    /// DD2 contains extended device information:
    /// - Bytes 0-1: Application manufacturer code (16-bit)
    /// - Bytes 2-3: Manufacturer-specific device type (16-bit)
    /// - Byte 4: Version of manufacturer-specific device type (8-bit)
    /// - Byte 5: Link management support (bit 7) + Logical tag base (bits 0-5)
    /// - Bytes 6-13: Channel information (4 channels, 2 bytes each)
    ///
    /// Set to `None` if DD2 is not supported. If `None`, the stack will return
    /// error code 0x3F when DD2 is requested.
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = None;

    /// User Manufacturer Info (3 bytes, optional).
    ///
    /// Contains:
    /// - Byte 0: KNX Manufacturer ID (8-bit)
    /// - Bytes 1-2: Manufacturer-specific data (16-bit)
    ///
    /// Set to `None` if not supported. If `None`, the stack will not respond
    /// to A_UserManufacturerInfo_Read requests.
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = None;

    /// Maximum incoming transport-layer connections (from remote devices).
    ///
    /// A typical KNX device accepts 1 incoming connection (from ETS or a
    /// configurator). Routers or gateways may need more. Default: 1.
    ///
    /// Note: Due to `generic_const_exprs` limitations, the default
    /// [`Runner::run()`] cannot forward these constants to the transport
    /// layer at compile time. The TL's own defaults (1/0) match these
    /// defaults. If you override these values, you'll need a custom runner
    /// that instantiates `TransportLayer` with explicit const generics.
    const TL_MAX_INCOMING: usize = 1;

    /// Maximum outgoing transport-layer connections (initiated by us).
    ///
    /// A typical KNX device has 0 outgoing connections. Routers or gateways
    /// that actively connect to other devices need more. Default: 0.
    ///
    /// Only valid with [`TlStyle::Style3`] or higher — the transport layer
    /// will panic at startup if `TL_MAX_OUTGOING > 0` with a style that
    /// does not support outgoing connections.
    const TL_MAX_OUTGOING: usize = 0;

    /// Transport layer state machine style per KNX spec 03/03/04 section 5.4.
    ///
    /// Determines connection-oriented error recovery behavior. Must be chosen
    /// explicitly — there is no default.
    const TL_STYLE: TlStyle;

    /// Mutex type for channels shared between the stack runner and user code.
    ///
    /// Use [`NoopRawMutex`]
    /// (default) when the stack runner and user code share the same executor.
    /// Use [`CriticalSectionRawMutex`](embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex)
    /// when the stack runs on an `InterruptExecutor` while user code runs on
    /// the thread executor — the interrupt executor can preempt mid-borrow,
    /// which requires a real mutex to prevent `BorrowMutError` panics.
    type Mutex: RawMutex + 'static = NoopRawMutex;

    type P: ConstDefault;
    type CO: ComObjects;
    type LLB: layers::LinkLayerBuilderBase + for<'a> layers::LinkLayerBuilder<StackContext<'a, Self>>;

    /// Unified device state containing both runtime state and tables.
    ///
    /// This type holds all device state:
    /// - Runtime state (individual address, authorization keys)
    /// - ETS-loaded tables (ADT, AST, COT, APP)
    ///
    /// Must implement [`StackState`] for runtime state access, and may implement
    /// table accessor traits for group object communication:
    /// - [`HasAddressTable`]
    /// - [`HasAssociationTable`]
    /// - [`HasCommunicationObjectTable`]
    ///
    /// For System B devices, use [`SystemBDeviceState`](bcus::system_b::SystemBDeviceState)
    /// or [`IpSystemBDeviceState`](bcus::system_b::IpSystemBDeviceState).
    type State: StackState + 'static;

    /// Memory map for A_Memory_Read/Write services.
    ///
    /// The memory map receives a reference to your `State` type when processing
    /// memory read/write requests. You implement the dispatch logic to map
    /// addresses to the appropriate tables stored in the state.
    ///
    /// Use [`memory::NoMemoryMap`] if you don't need memory services.
    type Mem: MemoryMap<Self::State> + 'static;

    /// Interface objects container type.
    ///
    /// This holds all interface objects for property service handling.
    /// The container must implement `PropertyServiceHandler` for property access.
    ///
    /// If the device has a DeviceObject, implement `HasDeviceObject` on this type
    /// to enable device-level configuration (programming mode, verify mode, etc.).
    /// This is required by [`Runner::run`] when running the stack.
    type InterfaceObjects<'a>: PropertyServiceHandler
    where
        Self::State: 'a;

    /// Create interface objects container.
    ///
    /// This method is called during stack initialization to create the interface
    /// objects that handle property service requests (A_PropertyValue_Read/Write, etc.).
    ///
    /// # Arguments
    /// * `state` - Reference to the unified device state (contains both runtime state and tables)
    ///
    /// # Returns
    /// The container holding all interface objects for this device.
    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a;

    /// Layer stack factory that handles channel creation, layer construction,
    /// and link-layer endpoint wiring.
    ///
    /// Use [`InsecureDeviceFactory`] for standard `(NL, TL, AL)` stacks or
    /// [`InsecureIpDeviceFactory`] for KNX/IP `(NL, CemiTL<TL>, AL)` stacks.
    type LayerFactory: LayerStackFactory<Self>;
}

// ============================================================================
// Layer composition
// ============================================================================

/// Context passed to [`LayerStackFactory::build`] for constructing the
/// layer stack.
///
/// Bundles all shared stack resources that protocol layers may need.
/// Custom layer stacks can pick the fields they care about and ignore
/// the rest.
pub struct LayerContext<'a, D: StackDefinition> {
    /// Buffer allocator for building outgoing messages.
    pub buffer_manager: &'a DynBufferManager<'static>,
    /// Unified device state (tables + runtime configuration).
    pub state: &'a D::State,
    /// Communication objects (group objects).
    pub comm_objs: &'a RefCell<D::CO>,
    /// Hook context for communication object hooks.
    pub hook_context: &'a <D::CO as ComObjects>::HookContext,
    /// Pub/sub channel for communication object events.
    pub event_channel:
        &'a PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
    /// Pub/sub channel for application lifecycle events.
    pub lifecycle_channel: &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
    /// Interface objects container for property service handling.
    pub interface_objects: &'a D::InterfaceObjects<'static>,
    /// Memory map for A_Memory_Read/Write services.
    pub memory_map: &'a D::Mem,
    /// Sender for restart requests from AL to user code.
    pub restart_sender: DynamicSender<'a, restart::RestartRequest>,
    /// Receiver for application service requests from user code
    /// (GroupValueWrite/Read via [`Stack::update_object`]).
    pub app_service_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
}

// ============================================================================
// Layer stack factories
// ============================================================================

/// Factory for constructing a layer stack and running its link layer.
///
/// Encapsulates channel creation, layer construction, and link-layer
/// endpoint extraction that were previously spread across multiple
/// `StackDefinition` items. Each factory knows:
///
/// - What shared channels are needed between layers and the link layer
/// - How to build the layer stack from a [`LayerContext`]
/// - How to extract link-layer endpoints and start the link layer
///
/// Two built-in factories are provided:
/// - [`InsecureDeviceFactory`] — standard `(NL, TL, AL)` stack, no extra channels
/// - [`InsecureIpDeviceFactory`] — `(NL, CemiTL<TL>, AL)` stack with cEMI channels
pub trait LayerStackFactory<D: StackDefinition>: Sized {
    /// Composed layer stack produced by [`build`](Self::build).
    type Stack<'a>: router::LayerStack
    where
        D: 'a;

    /// Owned channel storage shared between the layer stack and the link
    /// layer. Created as a stack-local in [`Runner::run()`] before layer
    /// construction, so both the router task and the LL task can borrow
    /// from it.
    ///
    /// `()` when no extra channels are needed (standard TP1 devices).
    type Channels: 'static;

    /// Create the shared channel storage.
    fn create_channels() -> Self::Channels;

    /// Build the layer stack from a [`LayerContext`] and the shared channels.
    fn build<'a>(ctx: &'a LayerContext<'a, D>, channels: &'a Self::Channels) -> Self::Stack<'a>
    where
        D: 'a;

    /// Start the link layer, extracting LL endpoints from the shared channels.
    ///
    /// The factory knows how to connect its channel type to the link layer
    /// builder's [`LLEndpoints`](layers::LinkLayerBuilderBase::LLEndpoints).
    fn run_link_layer<'a>(
        channels: &'a Self::Channels,
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: DynamicSender<'a, messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a;
}

/// Factory for standard `(NL, TL, AL)` layer stacks.
///
/// Produces [`InsecureDeviceLayers`] with no extra inter-layer channels.
/// The link layer builder must have `LLEndpoints = ()` (the default).
pub struct InsecureDeviceFactory;

impl<D: StackDefinition> LayerStackFactory<D> for InsecureDeviceFactory
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
    for<'a> <D::LLB as layers::LinkLayerBuilderBase>::LLEndpoints<'a>: Default,
    D::LLB: for<'a> layers::LinkLayerBuilder<StackContext<'a, D>>,
{
    type Stack<'a>
        = InsecureDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = ();

    fn create_channels() {}

    fn build<'a>(ctx: &'a LayerContext<'a, D>, channels: &'a ()) -> InsecureDeviceLayers<'a, D>
    where
        D: 'a,
    {
        InsecureDeviceLayers::new(ctx, channels)
    }

    fn run_link_layer<'a>(
        _channels: &'a (),
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: DynamicSender<'a, messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, Default::default(), ind_tx, conf_tx, req_rx)
    }
}

/// Factory for KNX/IP `(NL, CemiTL<TL>, AL)` layer stacks.
///
/// Produces [`InsecureIpDeviceLayers`] with a [`CemiTransportLayerChannelPair`](context::CemiTransportLayerChannelPair)
/// for Device Management connections. The link layer builder's
/// [`LLEndpoints`](layers::LinkLayerBuilderBase::LLEndpoints) must be
/// [`CemiTransportLayerEndpoints`](context::CemiTransportLayerEndpoints).
pub struct InsecureIpDeviceFactory;

impl<D: StackDefinition> LayerStackFactory<D> for InsecureIpDeviceFactory
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
    D::LLB: for<'a> layers::LinkLayerBuilder<
            StackContext<'a, D>,
            LLEndpoints<'a> = context::CemiTransportLayerEndpoints<'a>,
        >,
{
    type Stack<'a>
        = InsecureIpDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = context::CemiTransportLayerChannelPair;

    fn create_channels() -> context::CemiTransportLayerChannelPair {
        context::CemiTransportLayerChannelPair::new()
    }

    fn build<'a>(
        ctx: &'a LayerContext<'a, D>,
        channels: &'a context::CemiTransportLayerChannelPair,
    ) -> InsecureIpDeviceLayers<'a, D>
    where
        D: 'a,
    {
        InsecureIpDeviceLayers::new(ctx, channels)
    }

    fn run_link_layer<'a>(
        channels: &'a context::CemiTransportLayerChannelPair,
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: DynamicSender<'a, messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, channels.ll_endpoints(), ind_tx, conf_tx, req_rx)
    }
}

// ============================================================================
// Layer stack implementations
// ============================================================================

/// Standard layer stack: `(NetworkLayer, TransportLayer, ApplicationLayer)`.
///
/// This is the default layer composition for typical KNX devices.
/// It wraps the three standard protocol layers and manages the
/// application service channel as a side input.
///
/// Custom layer stacks can be created by implementing [`LayerStack`]
/// directly on a different type and using a custom [`LayerStackFactory`].
pub struct InsecureDeviceLayers<'a, D: StackDefinition> {
    layers: (NetworkLayer<'a, D>, TransportLayer<'a, D>, ApplicationLayer<'a, D>),
    app_service_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    pending_app_request: Cell<Option<Request<ApplicationLayerService, ApplicationLayerServiceResponse>>>,
}

impl<'a, D: StackDefinition> InsecureDeviceLayers<'a, D>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Construct the standard `(NL, TL, AL)` layer stack from a
    /// [`LayerContext`].
    pub fn new(ctx: &'a LayerContext<'a, D>, _channels: &'a ()) -> Self {
        let network_layer = NetworkLayer::new(ctx.state, ctx.interface_objects);

        // TODO: Use `{ D::TL_MAX_INCOMING }` and `{ D::TL_MAX_OUTGOING }` as const
        // generics here once `generic_const_exprs` no longer overflows for trait
        // consts forwarded through where-clauses.
        let transport_layer = TransportLayer::new(ctx.buffer_manager, ctx.state, D::TL_STYLE);

        let application_layer = ApplicationLayer::new(
            ctx.buffer_manager,
            ctx.state,
            ctx.comm_objs,
            ctx.hook_context,
            ctx.event_channel,
            ctx.lifecycle_channel,
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        Self {
            layers: (network_layer, transport_layer, application_layer),
            app_service_receiver: ctx.app_service_receiver,
            pending_app_request: Cell::new(None),
        }
    }
}

use router::LayerStack;

impl<D: StackDefinition> LayerStack for InsecureDeviceLayers<'_, D>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    const DISPATCH_TABLE: router::DispatchTable = {
        type Inner<'a, D> = (NetworkLayer<'a, D>, TransportLayer<'a, D>, ApplicationLayer<'a, D>);
        <Inner<'_, D> as LayerStack>::DISPATCH_TABLE
    };

    fn dispatch(&mut self, layer_idx: u8, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut router::Outbox) {
        self.layers.dispatch(layer_idx, msg, outbox);
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        self.layers.next_deadline()
    }

    fn poll(&mut self, outbox: &mut router::Outbox) {
        self.layers.poll(outbox);
    }

    fn init(&mut self) {
        self.layers.init();
    }

    fn recv_side_input(&self) -> impl core::future::Future<Output = ()> + '_ {
        async {
            let req = self.app_service_receiver.receive().await;
            self.pending_app_request.set(Some(req));
        }
    }

    fn handle_side_input(&mut self, outbox: &mut router::Outbox) {
        if let Some(req) = self.pending_app_request.take() {
            self.layers.2.handle_app_request(&req, outbox);
        }
    }
}

// ============================================================================
// InsecureIpDeviceLayers — with cEMI Transport Layer bridge
// ============================================================================

/// Layer stack for KNX/IP devices: `(NL, CemiTransportLayer<TL>, AL)`.
///
/// Extends [`InsecureDeviceLayers`] by wrapping the transport layer in a
/// [`CemiTransportLayer`](layers::transport::cemi::CemiTransportLayer) that
/// bridges KNX/IP Device Management connections with the application layer.
///
/// When a Device Management connection sends cEMI Transport Layer frames
/// (T_Data_Connected, T_Data_Individual), they are injected directly into
/// AL. AL responses are intercepted and routed back to the KNX/IP runtime.
///
/// Side inputs handled:
/// - Application service requests (from user code via [`Stack::update_object`])
/// - cEMI events (from DevMgmt handler: activate, deactivate, frame)
pub struct InsecureIpDeviceLayers<'a, D: StackDefinition> {
    layers: (NetworkLayer<'a, D>, layers::transport::cemi::CemiTransportLayer<'a, D>, ApplicationLayer<'a, D>),
    app_service_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    pending_app_request: Cell<Option<Request<ApplicationLayerService, ApplicationLayerServiceResponse>>>,
    cemi_event_receiver: DynamicReceiver<'a, layers::transport::cemi::CemiEvent>,
    pending_cemi_event: Cell<Option<layers::transport::cemi::CemiEvent>>,
}

impl<'a, D: StackDefinition> InsecureIpDeviceLayers<'a, D>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Construct the `(NL, CemiTL<TL>, AL)` layer stack from a
    /// [`LayerContext`] and a [`CemiTransportLayerChannelPair`](context::CemiTransportLayerChannelPair).
    pub fn new(ctx: &'a LayerContext<'a, D>, channels: &'a context::CemiTransportLayerChannelPair) -> Self {
        let network_layer = NetworkLayer::new(ctx.state, ctx.interface_objects);

        let transport_layer = TransportLayer::new(ctx.buffer_manager, ctx.state, D::TL_STYLE);

        let cemi_response_sender = channels.response.sender().into();
        let cemi_transport_layer =
            layers::transport::cemi::CemiTransportLayer::new(transport_layer, cemi_response_sender);

        let application_layer = ApplicationLayer::new(
            ctx.buffer_manager,
            ctx.state,
            ctx.comm_objs,
            ctx.hook_context,
            ctx.event_channel,
            ctx.lifecycle_channel,
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        let cemi_event_receiver = channels.event.receiver().into();

        Self {
            layers: (network_layer, cemi_transport_layer, application_layer),
            app_service_receiver: ctx.app_service_receiver,
            pending_app_request: Cell::new(None),
            cemi_event_receiver,
            pending_cemi_event: Cell::new(None),
        }
    }
}

impl<D: StackDefinition> LayerStack for InsecureIpDeviceLayers<'_, D>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    const DISPATCH_TABLE: router::DispatchTable = {
        type Inner<'a, D> =
            (NetworkLayer<'a, D>, layers::transport::cemi::CemiTransportLayer<'a, D>, ApplicationLayer<'a, D>);
        <Inner<'_, D> as LayerStack>::DISPATCH_TABLE
    };

    fn dispatch(&mut self, layer_idx: u8, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut router::Outbox) {
        self.layers.dispatch(layer_idx, msg, outbox);
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        self.layers.next_deadline()
    }

    fn poll(&mut self, outbox: &mut router::Outbox) {
        self.layers.poll(outbox);
    }

    fn init(&mut self) {
        self.layers.init();
    }

    fn recv_side_input(&self) -> impl core::future::Future<Output = ()> + '_ {
        use embassy_futures::select::{Either, select};

        async {
            match select(self.app_service_receiver.receive(), self.cemi_event_receiver.receive()).await {
                Either::First(req) => {
                    self.pending_app_request.set(Some(req));
                }
                Either::Second(event) => {
                    self.pending_cemi_event.set(Some(event));
                }
            }
        }
    }

    fn handle_side_input(&mut self, outbox: &mut router::Outbox) {
        if let Some(req) = self.pending_app_request.take() {
            self.layers.2.handle_app_request(&req, outbox);
        }
        if let Some(event) = self.pending_cemi_event.take() {
            self.layers.1.handle_cemi_event(event, outbox);
        }
    }
}

/// Pre-allocated resources for the KNX stack.
///
/// # Buffer Sizing
///
/// The buffer size should be calculated from [`StackDefinition::MAX_APDU_LENGTH`]
/// using [`config::buffer_size_for_apdu()`]. This includes:
/// - Frame overhead (9 bytes): for cEMI compatibility
/// - APDU data (up to `MAX_APDU_LENGTH`)
/// - Headroom (16 bytes): for zero-copy header prepending
///
/// # Example
///
/// ```ignore
/// use zweidraehte::config::{MAX_APDU_LENGTH_TP1_STANDARD, buffer_size_for_apdu};
///
/// impl StackDefinition for MyDevice {
///     const MASK_VERSION: &'static [u8; 2] = &[0x07, 0xB0];
///     const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_TP1_STANDARD; // 14 bytes
///     // ... other fields
/// }
///
/// // Buffer size is 39 bytes (14 + 9 overhead + 16 headroom)
/// static RESOURCES: StaticCell<StackResources<MyDevice, { buffer_size_for_apdu(MyDevice::MAX_APDU_LENGTH) }>> = StaticCell::new();
/// ```
///
/// # Type Parameters
///
/// - `D`: Your stack definition implementing [`StackDefinition`]
/// - `BUF_SZ`: Size of each buffer. Use `buffer_size_for_apdu(D::MAX_APDU_LENGTH)`
/// - `NUM_BUFS`: Number of buffers in the pool (default: 8). The cEMI device
///   management path can hold up to 4 buffers simultaneously, so values below
///   5 risk deadlocks under concurrent load.
///
/// # Note on Buffer Size
///
/// We would like to automatically derive `BUF_SZ` from `D::MAX_APDU_LENGTH`,
/// but Rust's `generic_const_exprs` feature is still incomplete and causes
/// overflow errors when used with static declarations. Until this is fixed,
/// users must explicitly specify the buffer size.
pub struct StackResources<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize = 8> {
    inner: MaybeUninit<Inner<D>>,
    buffers: MaybeUninit<[[u8; BUF_SZ]; NUM_BUFS]>,
    buffer_manager: MaybeUninit<BufferManager<NUM_BUFS>>,
    link_layer_resources: MaybeUninit<<D::LLB as LinkLayerBuilderBase>::Resources>,
    interface_objects: MaybeUninit<D::InterfaceObjects<'static>>,
}

impl<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize> Default for StackResources<D, BUF_SZ, NUM_BUFS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize> StackResources<D, BUF_SZ, NUM_BUFS> {
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
            buffers: MaybeUninit::uninit(),
            buffer_manager: MaybeUninit::uninit(),
            link_layer_resources: MaybeUninit::uninit(),
            interface_objects: MaybeUninit::uninit(),
        }
    }
}

/// KNX stack runner.
///
/// You must call [`Runner::run()`] in a background task for the KNX stack to work.
pub struct Runner<'d, D: StackDefinition> {
    stack: Stack<'d, D>,
    interface_objects: &'d D::InterfaceObjects<'static>,
    restart_sender: DynamicSender<'static, restart::RestartRequest>,
    link_layer_builder: D::LLB,
    link_layer_resources: &'d mut <D::LLB as LinkLayerBuilderBase>::Resources,
}

/// KNX stack handle for interacting with the KNX protocol stack.
///
/// This is the main interface for applications to interact with the KNX stack.
/// It provides methods to update and read communication objects, subscribe to
/// events, and debug the system. The handle is `Copy`, so you can pass it by
/// value instead of by reference, making it easy to share across tasks.
///
/// # Usage
/// The Stack handle is obtained by calling [`new()`] along with a [`Runner`].
/// The Runner must be executed in a background task for the stack to function.
///
/// # Example
/// ```rust,ignore
/// // Define your stack configuration types that implement the required traits
/// struct MyStackDefinition;
/// impl StackDefinition for MyStackDefinition {
///     const MASK_VERSION: &'static [u8; 2] = &[0x07, 0xb0];
///     type ADT = MyAddressTable;      // implements AddressTable
///     type AST = MyAssociationTable;  // implements AssociationTable
///     type COT = MyComObjectTable;    // implements CommunicationObjectTable
///     type P = MyParameters;          // implements ConstDefault
///     type CO = MyComObjects;         // implements ComObjects
///     type State = SystemBDeviceState<..>;  // implements StackState
/// }
///
/// // Create stack resources and configuration
/// let mut resources = StackResources::<MyStackDefinition>::new();
/// let (stack, runner) = new(&mut resources, addr_tab, asso_tab, co_tab, comm_objs);
///
/// // Start the stack runner in a background task
/// embassy_executor::Spawner::spawn(async { runner.run().await }).unwrap();
///
/// // Use the stack handle to interact with KNX
/// stack.update_object(object_index, new_value).await;
/// stack.read_object(object_index).await;
/// ```
///
/// For a complete working example with all the trait implementations,
/// see the `testutil` crate in this repository.
pub struct Stack<'d, D: StackDefinition> {
    inner: &'d Inner<D>,
    interface_objects: &'d D::InterfaceObjects<'static>,
    app_request_sender: DynamicSender<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    restart_receiver: DynamicReceiver<'static, restart::RestartRequest>,
}

impl<'d, D: StackDefinition> Copy for Stack<'d, D> {}

impl<'d, D: StackDefinition> Clone for Stack<'d, D> {
    fn clone(&self) -> Self {
        *self
    }
}

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
    fn with_comm_objs<R>(&self, f: impl FnOnce(&mut D::CO) -> R) -> R {
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

/// Combined context passed to [`LinkLayerBuilder::build_and_run()`].
///
/// Wraps references to the stack's internal state (for buffer management)
/// and interface objects (for property service access). Created in
/// [`Runner::run()`] where both are available.
/// Runtime context passed to link layers during [`Runner::run()`].
///
/// This is an opaque wrapper combining buffer management and property service
/// access. Link layers receive a `&StackContext` through
/// [`LinkLayerBuilder::build_and_run`]
/// and access its capabilities via the [`BufferManagerContext`] and
/// [`PropertyServiceContext`](context::PropertyServiceContext) trait impls.
pub struct StackContext<'a, D: StackDefinition> {
    inner: &'a Inner<D>,
    interface_objects: &'a D::InterfaceObjects<'static>,
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

impl<D: StackDefinition> context::PropertyServiceContext for StackContext<'_, D> {
    fn property_handler(&self) -> &dyn objects::interface::PropertyServiceHandler {
        self.interface_objects
    }
}

impl<D: StackDefinition> context::DeviceInfoContext for StackContext<'_, D>
where
    D::State: IpStackState,
{
    fn device_information(&self) -> messages::knxip::substructs::DeviceInformation {
        use messages::knxip::substructs::{DeviceInformation, DeviceStatus, KNXMedium};
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

    fn extended_device_information(&self) -> messages::knxip::substructs::ExtendedDeviceInformation {
        messages::knxip::substructs::ExtendedDeviceInformation {
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

impl<D: StackDefinition> context::IpDiagnosticsContext for StackContext<'_, D>
where
    D::State: IpStackState,
{
    fn ip_config(&self) -> messages::knxip::substructs::IpConfig {
        let state = &self.inner.state;
        messages::knxip::substructs::IpConfig {
            ip_address: state.configured_ip_address(),
            subnet_mask: state.configured_subnet_mask(),
            default_gateway: state.configured_default_gateway(),
            ip_capabilities: state.ip_capabilities(),
            ip_assignment_method: state.ip_assignment_method(),
        }
    }

    fn ip_current_config(&self) -> messages::knxip::substructs::IpCurrentConfig {
        let state = &self.inner.state;
        messages::knxip::substructs::IpCurrentConfig {
            ip_address: state.current_ip_address(),
            subnet_mask: state.current_subnet_mask(),
            default_gateway: state.current_default_gateway(),
            // TODO: Track DHCP server address in IpStackState when DHCP is implemented
            dhcp_server: core::net::Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: state.current_ip_assignment_method(),
        }
    }
}

impl<D: StackDefinition> context::IpAdditionalIndividualAddressContext for StackContext<'_, D>
where
    D::State: IpStackState,
{
    fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize {
        self.inner.state.write_additional_individual_addresses(buf)
    }
}

// Unconditional — `individual_address()` is on `StackState`, so this works
// for both IP and TP1 devices.
impl<D: StackDefinition> context::KnxIndividualAddressContext for StackContext<'_, D> {
    fn individual_address(&self) -> address::IndividualAddress {
        self.inner.state.individual_address()
    }
}

impl<D: StackDefinition> context::AddressTableContext for StackContext<'_, D>
where
    D::State: objects::tables::HasAddressTable,
{
    type ADT = <D::State as objects::tables::HasAddressTable>::ADT;

    fn address_table(&self) -> &core::cell::RefCell<Self::ADT> {
        self.inner.state.adt()
    }
}

fn _assert_covariant<'a, 'b: 'a, D: StackDefinition>(x: Stack<'b, D>) -> Stack<'a, D> {
    x
}

// fn create_request_response_pair<M: RawMutex, MSG, RESP, const N: usize>(
//     channel: &'static Channel<M, Request<MSG, RESP>, N>,
// ) -> (DynamicSender<'static, Request<MSG, RESP>>, DynamicReceiver<'static, Request<MSG, RESP>>) {
//     let sender: DynamicSender<'_, Request<MSG, RESP>> = channel.sender().into();
//     let receiver: DynamicReceiver<'_, Request<MSG, RESP>> = channel.receiver().into();
//     (sender.into(), receiver.into())
// }

fn create_request_response_pair<M: RawMutex, MSG, const N: usize>(
    channel: &'static Channel<M, MSG, N>,
) -> (DynamicSender<'static, MSG>, DynamicReceiver<'static, MSG>) {
    let sender: DynamicSender<'_, MSG> = channel.sender().into();
    let receiver: DynamicReceiver<'_, MSG> = channel.receiver().into();
    (sender, receiver)
}

/// Create a new KNX stack.
///
/// The `state` parameter contains the unified device state including:
/// - Individual address, authentication keys, and other runtime configuration
/// - ETS-loaded tables (ADT, AST, COT, APP)
///
/// Use the device state constructor or storage to create it:
/// - `SystemBDeviceState::new(storage.identity())` for fresh state
/// - `storage.load()` to restore from persistent storage
///
/// The `memory_map` parameter defines how memory addresses are mapped to tables
/// for A_Memory_Read/Write services. It must be configured with the same table
/// sizes as used for the device's tables (ADT, AST, COT sizes). Use
/// `SystemBMemoryMap::for_device()` with your device's MAX_ADDRESSES, MAX_ASSOCIATIONS,
/// etc. constants to create a properly configured memory map.
pub fn new<'d, D: StackDefinition + Copy, const BUF_SZ: usize, const NUM_BUFS: usize>(
    resources: &'d mut StackResources<D, BUF_SZ, NUM_BUFS>,
    comm_objs: D::CO,
    hook_context: <D::CO as ComObjects>::HookContext,
    link_layer_builder: D::LLB,
    state: D::State,
    memory_map: D::Mem,
) -> (Stack<'d, D>, Runner<'d, D>) {
    // Validate that runtime max_apdu_length doesn't exceed compile-time buffer allocation
    let runtime_max_apdu = state.max_apdu_length();
    assert!(
        runtime_max_apdu <= D::MAX_APDU_LENGTH,
        "StackState::max_apdu_length() ({}) exceeds StackDefinition::MAX_APDU_LENGTH ({}). \
         The runtime limit must not exceed the compile-time buffer allocation.",
        runtime_max_apdu,
        D::MAX_APDU_LENGTH
    );

    // SAFETY: We are creating a reference to the buffers that are stored in the `StackResources` struct,
    //         which lives at least as long as `Inner`
    let buffers = resources.buffers.write([[0; _]; _]);
    let buffer_manager: &'static mut BufferManager<NUM_BUFS> =
        unsafe { core::mem::transmute(resources.buffer_manager.write(BufferManager::new(buffers))) };

    let inner = Inner {
        buffer_manager: buffer_manager.dyn_buffer_manager(),
        app_service_channel: Channel::new(),
        comm_objs: RefCell::new(comm_objs),
        event_channel: PubSubChannel::new(),
        lifecycle_channel: PubSubChannel::new(),
        restart_channel: Channel::new(),
        state,
        hook_context,
        memory_map,
    };

    let inner = &*resources.inner.write(inner);

    // Build interface objects with reference to the state stored in Inner.
    // SAFETY: Inner is now stable in memory (written to StackResources), so we can safely
    //         transmute the state reference to 'static lifetime. The actual lifetime is 'd
    //         but the interface objects container needs 'static for its type parameter.
    let interface_objects = {
        let state_ref: &'static D::State = unsafe { core::mem::transmute(&inner.state) };
        D::create_interface_objects(state_ref)
    };
    let interface_objects = &*resources.interface_objects.write(interface_objects);

    // SAFETY: We are creating a static reference to the channel held by the `Inner` struct,
    //         which is safe because it is guaranteed to live as long as the `Stack` or the `Runner`.
    let app_request_sender: DynamicSender<'static, _> = unsafe {
        core::mem::transmute::<DynamicSender<'_, _>, DynamicSender<'static, _>>(
            inner.app_service_channel.sender().into(),
        )
    };

    // Create restart channel sender/receiver pair.
    // The sender goes to the Runner (passed to ApplicationLayer), receiver goes to Stack (for user code).
    let (restart_sender, restart_receiver) =
        create_request_response_pair::<D::Mutex, _, 1>(unsafe { core::mem::transmute(&inner.restart_channel) });

    // Initialize link layer resources using the builder
    let link_layer_resources = resources.link_layer_resources.write(link_layer_builder.create_resources());

    let stack = Stack { inner, interface_objects, app_request_sender, restart_receiver };
    let runner = Runner { stack, interface_objects, restart_sender, link_layer_builder, link_layer_resources };

    (stack, runner)
}

impl<'d, D: StackDefinition> Runner<'d, D> {
    /// Run the KNX stack.
    ///
    /// You must call this in a background task, to process KNX messages.
    // FIXME: Figure out how to get rid of the trait bounds here on all the tables
    //        Problem is all the process() methods in the layers require these traits
    pub async fn run(self) -> !
    where
        D::State: HasAddressTable
            + HasApplication
            + HasAssociationTable
            + HasCommunicationObjectTable
            + HasConnectionAuth
            + HasRoutingCount,
        D::InterfaceObjects<'static>: HasDeviceObject,
    {
        // Validate that outgoing connections require Style 3 (which has the
        // CONNECTING state needed for client-initiated connections).
        assert!(
            D::TL_MAX_OUTGOING == 0 || D::TL_STYLE == TlStyle::Style3,
            "TL_MAX_OUTGOING > 0 requires TlStyle::Style3 (has CONNECTING state for client connections)"
        );

        // Initialize the run state machine at startup.
        // If the application is already loaded (from persistent storage), this will
        // transition it to RUNNING.
        self.stack.inner.state.app().borrow_mut().init_run_state();

        // Sync the DeviceControl user_stopped bit based on run state.
        let is_running = self.stack.inner.state.app().borrow().is_running();
        self.interface_objects.set_user_stopped(!is_running);

        // Publish initial lifecycle event so user code can initialize if the
        // application is already loaded from persisted state.
        if is_running {
            self.stack.inner.lifecycle_channel.publish_immediate(LifecycleEvent::ApplicationStarted);
        }

        use embassy_futures::select::{Either, select, select3};
        use embassy_time::Timer;
        use messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};
        use messages::knx::ServiceType;
        use router::{LayerStack, Outbox};

        // ================================================================
        // Link layer channels
        // ================================================================
        //
        // The link layer stays as a separate async task connected via three
        // channels. The router replaces the inter-layer channels (NL↔TL,
        // TL↔AL) with a synchronous dispatch table.

        let ll_req: Channel<NoopRawMutex, RequestMessage<Buffer<'static>>, 1> = Channel::new();
        let ll_ind: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 1> = Channel::new();
        let ll_conf: Channel<NoopRawMutex, ConfirmationMessage<Buffer<'static>>, 1> = Channel::new();

        // ================================================================
        // Shared inter-layer channels (driven by LayerStackFactory)
        // ================================================================
        //
        // The factory decides what shared channels are needed between
        // layers and the link layer. For InsecureIpDeviceFactory this is
        // a CemiTransportLayerChannelPair; for InsecureDeviceFactory it's ().

        type F<D> = <D as StackDefinition>::LayerFactory;
        type Layers<'a, D> = <F<D> as LayerStackFactory<D>>::Stack<'a>;

        let layer_channels = F::<D>::create_channels();

        // ================================================================
        // Layer construction (via LayerStackFactory)
        // ================================================================

        // SAFETY: We are creating a static reference to the channel held by the `Inner` struct.
        // This is safe because `Inner` lives in `StackResources` which outlives this function.
        let app_service_receiver: DynamicReceiver<'static, _> = unsafe {
            core::mem::transmute::<DynamicReceiver<'_, _>, DynamicReceiver<'static, _>>(
                self.stack.inner.app_service_channel.receiver().into(),
            )
        };

        let layer_context = LayerContext {
            buffer_manager: &self.stack.inner.buffer_manager,
            state: &self.stack.inner.state,
            comm_objs: &self.stack.inner.comm_objs,
            hook_context: &self.stack.inner.hook_context,
            event_channel: &self.stack.inner.event_channel,
            lifecycle_channel: &self.stack.inner.lifecycle_channel,
            interface_objects: self.interface_objects,
            memory_map: &self.stack.inner.memory_map,
            restart_sender: self.restart_sender,
            app_service_receiver,
        };

        let mut layers = F::<D>::build(&layer_context, &layer_channels);

        // Initialize all layers (e.g., AL starts read-on-init cycle if
        // the application is already running).
        layers.init();

        // ================================================================
        // Link layer task
        // ================================================================

        let stack_context = StackContext { inner: self.stack.inner, interface_objects: self.interface_objects };
        let ll_task = F::<D>::run_link_layer(
            &layer_channels,
            self.link_layer_builder,
            self.link_layer_resources,
            &stack_context,
            ll_ind.sender().into(),
            ll_conf.sender().into(),
            ll_req.receiver(),
        );

        // ================================================================
        // Router dispatch loop
        // ================================================================
        //
        // A single async loop replaces the previous 3 concurrent layer
        // tasks. Messages flow through the synchronous dispatch table:
        //
        //   LL → (L_Data_Ind) → NL → (N_*_Ind) → TL → (T_*_Ind) → AL
        //   AL → (T_*_Req)    → TL → (N_*_Req) → NL → (L_Data_Req) → LL
        //
        // Each ServiceType maps to exactly one layer. The outbox collects
        // outputs; the drain loop re-dispatches until all messages are
        // consumed or sent to the LL.
        //
        // The router is fully generic: it only uses the `LayerStack` trait.
        // Side inputs (e.g., app service requests from user code) are
        // handled through `recv_side_input` / `handle_side_input`.

        let router_task = async {
            loop {
                let mut outbox = Outbox::new();

                let layer_deadline = layers.next_deadline();
                if layer_deadline.is_some() {
                    debug!("Router: layer_deadline is Some, will poll on timer");
                }

                // Wait for the next event: LL indication, LL confirmation,
                // layer side input, or layer timer.
                match select3(
                    ll_ind.receive(),
                    ll_conf.receive(),
                    select(layers.recv_side_input(), async {
                        match layer_deadline {
                            Some(deadline) => Timer::at(deadline).await,
                            // No deadline → sleep forever (select will pick
                            // another branch).
                            None => core::future::pending().await,
                        }
                    }),
                )
                .await
                {
                    // LL indication → push to outbox for dispatch
                    embassy_futures::select::Either3::First(ind) => {
                        outbox.push(ind.into_inner());
                    }
                    // LL confirmation → push to outbox for dispatch
                    embassy_futures::select::Either3::Second(conf) => {
                        outbox.push(conf.into_inner());
                    }
                    embassy_futures::select::Either3::Third(third) => {
                        match third {
                            // Side input resolved → let layers process it
                            Either::First(()) => {
                                layers.handle_side_input(&mut outbox);
                            }
                            // Timer expired → poll layers with expired deadlines
                            Either::Second(_) => {
                                debug!("Router: timer expired, polling layers");
                                layers.poll(&mut outbox);
                            }
                        }
                    }
                }

                // Drain the outbox: dispatch each message through the table
                // until all messages are consumed or sent to the LL.
                while let Some(msg) = outbox.take_next() {
                    let st = msg.service_type();
                    if st == ServiceType::L_Data_Req {
                        // Terminal: send to link layer
                        ll_req.send(RequestMessage::request(msg)).await;
                    } else if let Some(layer_idx) = Layers::<'_, D>::DISPATCH_TABLE.get(st) {
                        layers.dispatch(layer_idx, msg, &mut outbox);
                    } else {
                        warn!("Router: no layer for {:?}, dropping", st);
                        // Buffer is dropped, returned to pool
                    }
                }
            }
        };

        // Run link layer and router concurrently
        embassy_futures::join::join(ll_task, router_task).await;

        unreachable!();
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    /// Update a communication object with a new value and send it to the KNX bus.
    ///
    /// This method updates the local communication object value and sends a GroupValueWrite
    /// request to the KNX bus to inform other devices of the change.
    ///
    /// # Arguments
    /// * `asap` - The communication object index to update
    /// * `value` - The new value to set. Must implement `AsRef<[u8]>` to provide the raw bytes
    ///
    /// # Behavior
    /// 1. Sets the communication object status to `WriteRequest`
    /// 2. Updates the local object value with the provided data
    /// 3. Publishes a `LocallyUpdated` event to notify subscribers
    /// 4. Sends a GroupValueWrite request to the KNX bus
    ///
    /// # Returns
    /// * `Ok(())` - The update was accepted and will be transmitted
    /// * `Err(UpdateObjectError::Busy)` - The object is already transmitting
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>, switch_index: MyComObjectIndex) {
    /// use zweidraehte::dpt::DPT_Switch;
    ///
    /// // Update a boolean switch object
    /// if stack.update_object(switch_index, DPT_Switch::from(true)).await.is_ok() {
    ///     println!("Update accepted");
    /// }
    /// # }
    /// ```
    pub async fn update_object<T: AsRef<[u8]>>(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
        value: T,
    ) -> Result<(), UpdateObjectError> {
        // Reject only if the object is actively being transmitted (Busy).
        let accepted = self.inner.with_comm_objs(|co| {
            if co.status(asap.index()) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap.index(), ComObjectStatus::WriteRequest);
            co.info_mut(asap.index()).value.copy_from_slice(value.as_ref());
            true
        });

        if !accepted {
            return Err(UpdateObjectError::Busy);
        }

        self.inner.event_channel.publish_immediate((asap.clone(), ComObjectEvent::LocallyUpdated));

        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueWriteRequest(asap.index()),
        )
        .await;
        Ok(())
    }

    /// Send a write request for a communication object using its current value.
    ///
    /// Unlike `update_object`, this method does not modify the object's value - it simply
    /// sends the current value to the KNX bus. This is useful when the value has already
    /// been set through other means (e.g., via a shadow object in conformance testing).
    ///
    /// # Arguments
    /// * `asap` - The communication object index to send
    ///
    /// # Behavior
    /// 1. Sets the communication object status to `WriteRequest`
    /// 2. Sends a GroupValueWrite request with the object's current value to the KNX bus
    ///
    /// Note: This does NOT publish a `LocallyUpdated` event since the value is not being
    /// changed, only transmitted.
    ///
    /// # Returns
    /// * `Ok(())` - The write request was accepted
    /// * `Err(UpdateObjectError::Busy)` - The object is already transmitting
    pub async fn write_object(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
    ) -> Result<(), UpdateObjectError> {
        self.write_object_by_asap(asap.index()).await
    }

    /// Send a write request for a communication object by ASAP number.
    ///
    /// This is a lower-level version of `write_object` that takes a raw ASAP number
    /// instead of the type-safe Index type.
    ///
    /// # Returns
    /// * `Ok(())` - The write request was accepted
    /// * `Err(UpdateObjectError::Busy)` - The object is already transmitting
    pub async fn write_object_by_asap(&self, asap: u16) -> Result<(), UpdateObjectError> {
        let accepted = self.inner.with_comm_objs(|co| {
            // Reject only if the object is actively being transmitted (Busy).
            // Other states (including WriteRequest set via flag manipulation)
            // are fine — the AL serializes requests through a size-1 channel.
            if co.status(asap) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap, ComObjectStatus::WriteRequest);
            true
        });

        if !accepted {
            return Err(UpdateObjectError::Busy);
        }

        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueWriteRequest(asap),
        )
        .await;
        Ok(())
    }

    /// Send a read request for a communication object.
    ///
    /// This method sends the read request and returns immediately without waiting for a response.
    /// Use `read_object_with_timeout` if you need to wait for the response.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was accepted
    /// * `Err(ReadObjectError::Busy)` - The object is already transmitting
    pub async fn read_object(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
    ) -> Result<(), ReadObjectError> {
        self.read_object_by_asap(asap.index()).await
    }

    /// Send a read request for a communication object by ASAP number.
    ///
    /// This is a lower-level version of `read_object` that takes a raw ASAP number
    /// instead of the type-safe Index type.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was accepted
    /// * `Err(ReadObjectError::Busy)` - The object is already transmitting
    pub async fn read_object_by_asap(&self, asap: u16) -> Result<(), ReadObjectError> {
        let accepted = self.inner.with_comm_objs(|co| {
            // Reject only if the object is actively being transmitted (Busy).
            if co.status(asap) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap, ComObjectStatus::ReadRequest);
            true
        });

        if !accepted {
            return Err(ReadObjectError::Busy);
        }

        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueReadRequest(asap),
        )
        .await;
        Ok(())
    }

    /// Send a read request for a communication object and optionally wait for the response.
    ///
    /// # Arguments
    /// * `asap` - The communication object index to read
    /// * `timeout` - Optional timeout duration. If `None`, the method returns immediately after
    ///               sending the request (same behavior as `read_object`). If `Some(duration)`,
    ///               it waits for a `ReadResponse` event for up to the specified duration.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was sent successfully and (if timeout was specified) a response was received
    /// * `Err(ReadObjectError::Timeout)` - A timeout was specified but no response was received within the timeout period
    /// * `Err(ReadObjectError::Busy)` - The object is already transmitting
    ///
    /// # Example
    /// ```rust,ignore
    /// # use embassy_time::Duration;
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>, asap: MyComObjectIndex) {
    /// // Fire-and-forget read request
    /// let _ = stack.read_object(asap).await;
    ///
    /// // Read request with 1 second timeout
    /// match stack.read_object_with_timeout(asap, Some(Duration::from_secs(1))).await {
    ///     Ok(()) => println!("Response received!"),
    ///     Err(zweidraehte::ReadObjectError::Timeout) => println!("No response within timeout"),
    ///     Err(zweidraehte::ReadObjectError::Busy) => println!("Object is busy"),
    /// }
    /// # }
    /// ```
    pub async fn read_object_with_timeout(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
        timeout: Option<Duration>,
    ) -> Result<(), ReadObjectError> {
        // Reject only if the object is actively being transmitted (Busy).
        let accepted = self.inner.with_comm_objs(|co| {
            if co.status(asap.index()) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap.index(), ComObjectStatus::ReadRequest);
            true
        });

        if !accepted {
            return Err(ReadObjectError::Busy);
        }

        // If no timeout is specified, just send the request and return immediately
        let Some(timeout_duration) = timeout else {
            ActorRequest::<D::Mutex, _, _>::request(
                &self.app_request_sender,
                ApplicationLayerService::GroupValueReadRequest(asap.index()),
            )
            .await;
            return Ok(());
        };

        // Subscribe to events before sending the request to avoid race conditions
        let mut event_subscriber = self.events();

        // Send the read request
        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueReadRequest(asap.index()),
        )
        .await;

        // Wait for ReadResponse event with timeout
        let wait_for_response = async {
            loop {
                let event = event_subscriber.next_message_pure().await;
                let (event_asap, event_type) = event;
                if event_asap.index() == asap.index() {
                    match event_type {
                        ComObjectEvent::ReadResponse => {
                            return;
                        }
                        ComObjectEvent::Updated | ComObjectEvent::LocallyUpdated | ComObjectEvent::Read => {
                            // Continue waiting - these are not read responses
                            continue;
                        }
                    }
                }
                // Event for different object, keep waiting
            }
        };

        match with_timeout(timeout_duration, wait_for_response).await {
            Ok(()) => Ok(()),
            Err(TimeoutError) => Err(ReadObjectError::Timeout),
        }
    }

    /// Get access to the communication objects container.
    ///
    /// Returns a reference to the `RefCell` containing all communication objects.
    /// Use this to read object values, check statuses, or perform other operations
    /// on the communication objects.
    ///
    /// # Returns
    /// A reference to the `RefCell<D::CO>` containing all communication objects
    ///
    /// # Example
    /// ```rust,ignore
    /// # fn example(stack: zweidraehte::Stack<'_, MyStackDef>, switch_index: MyComObjectIndex) {
    /// // Read the current value of a communication object
    /// let objects = stack.objects();
    /// let current_value = objects.borrow().value(switch_index.index());
    ///
    /// // Check the status of a communication object
    /// let status = objects.borrow().status(switch_index.index());
    /// println!("Object status: {:?}", status);
    /// # }
    /// ```
    pub fn objects(&self) -> &RefCell<D::CO> {
        &self.inner.comm_objs
    }

    /// Get access to the interface objects container.
    ///
    /// Returns a reference to the interface objects container created during
    /// stack initialization. The container type is determined by the
    /// `InterfaceObjects` associated type in the `StackDefinition`.
    ///
    /// # Returns
    /// A reference to the interface objects container
    pub fn interface_objects(&self) -> &D::InterfaceObjects<'static> {
        self.interface_objects
    }

    /// Subscribe to communication object events.
    ///
    /// Returns a subscriber that receives events when communication objects are updated.
    /// This is useful for monitoring changes to objects caused by incoming KNX messages
    /// or local updates.
    ///
    /// # Returns
    /// A `DynSubscriber` that yields tuples of `(object_index, event_type)`
    ///
    /// # Events
    /// * `ComObjectEvent::Updated` - Object was updated by an incoming GroupValueWrite
    /// * `ComObjectEvent::LocallyUpdated` - Object was updated locally via `update_object`
    /// * `ComObjectEvent::ReadResponse` - A response to a read request was received
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>) {
    /// use embassy_sync::pubsub::WaitResult;
    /// use zweidraehte::objects::comm::ComObjectEvent;
    ///
    /// let mut events = stack.events();
    ///
    /// loop {
    ///     match events.next_message().await {
    ///         WaitResult::Message((index, event)) => {
    ///             match event {
    ///                 ComObjectEvent::Updated => {
    ///                     println!("Object {:?} was updated remotely", index);
    ///                 }
    ///                 ComObjectEvent::LocallyUpdated => {
    ///                     println!("Object {:?} was updated locally", index);
    ///                 }
    ///                 ComObjectEvent::ReadResponse => {
    ///                     println!("Received read response for object {:?}", index);
    ///                 }
    ///             }
    ///         }
    ///         WaitResult::Lagged(count) => {
    ///             println!("Missed {} events due to slow processing", count);
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub fn events(
        &self,
    ) -> embassy_sync::pubsub::DynSubscriber<'_, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent)>
    {
        self.inner.event_channel.dyn_subscriber().unwrap()
    }

    /// Subscribe to application lifecycle events.
    ///
    /// Returns a subscriber that receives events when the application transitions
    /// into or out of the RUNNING state. This includes transitions caused by:
    /// - ETS programming completing (load state machine cascade)
    /// - Explicit run state control commands
    /// - Device startup with persisted loaded state
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>) {
    /// use zweidraehte::prelude::LifecycleEvent;
    ///
    /// let mut lifecycle = stack.lifecycle_events();
    ///
    /// loop {
    ///     match lifecycle.next_message_pure().await {
    ///         LifecycleEvent::ApplicationStarted => {
    ///             // Read parameters, initialize outputs, start timers
    ///         }
    ///         LifecycleEvent::ApplicationStopped => {
    ///             // Set outputs to safe state, stop timers
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub fn lifecycle_events(&self) -> embassy_sync::pubsub::DynSubscriber<'_, LifecycleEvent> {
        self.inner.lifecycle_channel.dyn_subscriber().unwrap()
    }

    /// Allocate a KNX message buffer from raw bytes.
    ///
    /// This is useful for testing and debugging, particularly with mock link layers
    /// where you want to inject messages into the stack.
    ///
    /// # Arguments
    /// * `msg` - Raw message bytes to allocate into a buffer
    ///
    /// # Returns
    /// A `KnxMessageBuffer` that can be injected into a mock link layer
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(
    /// #     stack: zweidraehte::Stack<'_, MyStackDef>,
    /// #     mock_ll: zweidraehte::layers::linklayers::mock::MockLinkLayerHandle
    /// # ) {
    /// use zweidraehte::messages::knx::ServiceType;
    ///
    /// // Allocate a message buffer
    /// let msg = stack.alloc_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x81]).await;
    ///
    /// // Inject it into the mock link layer
    /// mock_ll.inject(msg).await;
    /// # }
    /// ```
    pub async fn alloc_message(&self, msg: &[u8]) -> KnxMessageBuffer<Buffer<'static>> {
        let buffer = self.inner.buffer_manager.alloc_from_slice(msg).await;
        KnxMessageBuffer::new(buffer, messages::knx::ServiceType::L_Data_Ind)
    }

    /// Get the device's individual address.
    ///
    /// This is the unique address assigned to this device on the KNX bus.
    /// It is used as the source address for outgoing messages.
    ///
    /// # Returns
    /// The device's individual address
    pub fn individual_address(&self) -> IndividualAddress {
        self.inner.state.individual_address()
    }

    /// Set the device's individual address.
    ///
    /// This is typically set during device configuration or via
    /// `A_IndividualAddress_Write` when in programming mode.
    ///
    /// # Arguments
    /// * `addr` - The new individual address
    pub fn set_individual_address(&self, addr: IndividualAddress) {
        self.inner.state.set_individual_address(addr);
    }

    /// Get access to the runtime state.
    ///
    /// Returns a reference to the runtime state containing programming mode
    /// and other shared configuration.
    pub fn state(&self) -> &D::State {
        &self.inner.state
    }

    /// Get access to the hook context for communication object hooks.
    ///
    /// This is useful for setting up hook context after stack initialization,
    /// for example when the hook context needs references to stack-internal
    /// structures like the COT.
    pub fn hook_context(&self) -> &<D::CO as ComObjects>::HookContext {
        &self.inner.hook_context
    }

    /// Receive the next restart request from the application layer.
    ///
    /// When the stack receives an A_Restart message from the KNX bus, it validates
    /// the request, sends the bus response immediately, and forwards the request
    /// here for user code to act on. User code should:
    ///
    /// 1. Call this method to receive the request
    /// 2. Execute the appropriate reset based on [`restart::EraseCode`]
    /// 3. Flush storage to persist any changes
    /// 4. Trigger platform restart
    ///
    /// The bus response (A_Restart_Response) is sent by the application layer
    /// before this request arrives — no response channel is needed.
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn handle_restart(stack: zweidraehte::Stack<'_, MyDevice>) {
    /// use zweidraehte::restart::{RestartRequest, EraseCode};
    ///
    /// loop {
    ///     let request = stack.receive_restart_request().await;
    ///
    ///     // Execute reset based on erase code
    ///     match request.erase_code {
    ///         EraseCode::Basic | EraseCode::Confirmed => {}
    ///         EraseCode::FactoryReset => {
    ///             device_state.factory_reset();
    ///         }
    ///         _ => continue, // Unsupported erase code — AL already rejected on bus
    ///     }
    ///
    ///     // Trigger platform restart
    ///     embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
    ///     use platform::SystemControl;
    ///     let mut system = platform::LinuxSystem;
    ///     let Err(e) = system.restart().await;
    ///     panic!("Failed to restart: {:?}", e);
    /// }
    /// # }
    /// ```
    pub async fn receive_restart_request(&self) -> restart::RestartRequest {
        self.restart_receiver.receive().await
    }

    /// Returns the current buffer pool usage as `(allocated, total)`.
    ///
    /// Useful for monitoring pool pressure and diagnosing potential deadlocks
    /// in production. When `allocated` approaches `total`, incoming allocations
    /// may block.
    pub fn buffer_pool_status(&self) -> (u8, u8) {
        let bm = &self.inner.buffer_manager;
        (bm.allocated_count(), bm.pool_size())
    }
}

// Table accessor methods - only available when State implements the appropriate traits
impl<'d, D: StackDefinition> Stack<'d, D>
where
    D::State: HasAddressTable,
{
    /// Get access to the address table.
    ///
    /// Returns a reference to the `RefCell` containing the address table.
    /// The address table maps TSAPs (Transport Service Access Points) to group addresses.
    ///
    /// # Returns
    /// A reference to the `RefCell` containing the address table
    pub fn address_table(&self) -> &RefCell<<D::State as HasAddressTable>::ADT> {
        self.inner.state.adt()
    }
}

impl<'d, D: StackDefinition> Stack<'d, D>
where
    D::State: HasAssociationTable,
{
    /// Get access to the association table.
    ///
    /// Returns a reference to the `RefCell` containing the association table.
    /// The association table maps TSAPs to ASAPs (Application Service Access Points).
    ///
    /// # Returns
    /// A reference to the `RefCell` containing the association table
    pub fn association_table(&self) -> &RefCell<<D::State as HasAssociationTable>::AST> {
        self.inner.state.ast()
    }
}

impl<'d, D: StackDefinition> Stack<'d, D>
where
    D::State: HasCommunicationObjectTable,
{
    /// Get access to the communication object table.
    ///
    /// Returns a reference to the `RefCell` containing the communication object table.
    /// The communication object table contains type and flag information for each
    /// communication object (separate from the values stored in `objects()`).
    ///
    /// # Returns
    /// A reference to the `RefCell` containing the communication object table
    pub fn communication_object_table(&self) -> &RefCell<<D::State as HasCommunicationObjectTable>::COT> {
        self.inner.state.cot()
    }
}

impl<'d, D: StackDefinition> Stack<'d, D>
where
    D::State: HasApplication,
{
    /// Check if the application is currently running.
    ///
    /// The application is running when the run state machine is in the RUNNING state.
    /// This requires the application program to be loaded (either from ETS programming
    /// or from persisted state).
    pub fn is_running(&self) -> bool {
        self.inner.state.app().borrow().is_running()
    }
}
