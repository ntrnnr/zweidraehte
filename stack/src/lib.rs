#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
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
pub mod storage;
pub mod util;

use core::{
    cell::RefCell,
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
        ActorRequest, Layer, LayerOp, LinkLayerBuilder, LinkLayerBuilderBase, Request,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        transport::{TransportLayer, TlStyle},
    },
    memory::MemoryMap,
    messages::buffers::{Buffer, BufferManager, DynBufferManager},
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects},
        interface::{HasDeviceObject, PropertyServiceHandler},
        tables::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasRunStateMachine},
    },
};

/// Error type for read object operations with timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadObjectError {
    /// The read request timed out without receiving a response
    Timeout,
    /// The object is busy (already transmitting)
    Busy,
}

/// Error type for update/write object operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// For a device with keys[0]=0x00, keys[1]=0x12345678, keys[2]=0xFF..FF, keys[3]=0xFF..FF,
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
    /// - `current_access_level`: The current access level of the connection
    ///
    /// Returns the level if successful, or 0xFF if:
    /// - The level is invalid (>= max_access_levels)
    /// - The current access level is higher than the target level
    ///
    /// If key is `0xFFFFFFFF`, the key for that level is deleted (set to invalid).
    ///
    /// Default implementation: always returns 0xFF (not supported).
    fn key_write(&self, _level: u8, _key: &[u8; 4], _current_access_level: u8) -> u8 {
        0xFF // Not supported by default
    }
}

/// Number of authorization access levels supported (0-3).
pub const MAX_ACCESS_LEVELS: usize = 4;

/// Number of settable authorization keys (levels 0-2).
/// Level 3 is "access for everyone" and has no key - it's what you get when auth fails.
pub const NUM_AUTH_KEYS: usize = 3;

// ============================================================================
// IP Stack State Extension
// ============================================================================

use core::net::Ipv4Addr;

/// Extended stack state for KNXnet/IP devices.
///
/// This trait extends [`StackState`] with IP-specific configuration and
/// platform queries needed by [`IpParameterObject`].
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
/// trait bound, so [`IpParameterObject`] uses `S: IpDevice` instead of
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

    /// Transport layer state machine style per KNX spec 03/03/04 section 5.4.
    ///
    /// Determines connection-oriented error recovery behavior. Must be chosen
    /// explicitly — there is no default.
    const TL_STYLE: TlStyle;

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
    /// - [`HasAddressTable`](objects::tables::HasAddressTable)
    /// - [`HasAssociationTable`](objects::tables::HasAssociationTable)
    /// - [`HasCommunicationObjectTable`](objects::tables::HasCommunicationObjectTable)
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
    app_request_receiver: DynamicReceiver<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    restart_sender: DynamicSender<'static, Request<restart::RestartRequest, restart::RestartResponse>>,
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
    restart_receiver: DynamicReceiver<'static, Request<restart::RestartRequest, restart::RestartResponse>>,
}

impl<'d, D: StackDefinition> Copy for Stack<'d, D> {}

impl<'d, D: StackDefinition> Clone for Stack<'d, D> {
    fn clone(&self) -> Self {
        *self
    }
}

pub(crate) struct Inner<D: StackDefinition> {
    pub(crate) buffer_manager: RefCell<DynBufferManager<'static>>,
    pub(crate) app_service_channel:
        Channel<NoopRawMutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,
    pub(crate) comm_objs: RefCell<D::CO>,
    pub(crate) event_channel:
        PubSubChannel<NoopRawMutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
    /// Channel for A_Restart requests from application layer to user code
    pub(crate) restart_channel:
        Channel<NoopRawMutex, Request<restart::RestartRequest, restart::RestartResponse>, 1>,
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
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
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
/// [`LinkLayerBuilder::build_and_run`](layers::LinkLayerBuilder::build_and_run)
/// and access its capabilities via the [`BufferManagerContext`] and
/// [`PropertyServiceContext`](context::PropertyServiceContext) trait impls.
pub struct StackContext<'a, D: StackDefinition> {
    inner: &'a Inner<D>,
    interface_objects: &'a D::InterfaceObjects<'static>,
    al_sender: embassy_sync::channel::DynamicSender<'a, layers::LayerOp<messages::buffers::Buffer<'static>>>,
}

impl<D: StackDefinition> BufferManagerContext for StackContext<'_, D> {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
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

impl<D: StackDefinition> context::ApplicationLayerContext for StackContext<'_, D> {
    fn application_layer_sender(
        &self,
    ) -> embassy_sync::channel::DynamicSender<'_, layers::LayerOp<messages::buffers::Buffer<'static>>> {
        self.al_sender.clone()
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
            device_status: if state.is_programming_mode() {
                DeviceStatus::ProgrammingMode
            } else {
                DeviceStatus::None
            },
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

// Unconditional — `individual_address()` is on `StackState`, not `IpStackState`,
// so this works for both IP and TP1 devices. `additional_individual_addresses()`
// returns `&[]` by default until tunneling is implemented.
impl<D: StackDefinition> context::KnxAddressContext for StackContext<'_, D> {
    fn individual_address(&self) -> address::IndividualAddress {
        self.inner.state.individual_address()
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
    (sender.into(), receiver.into())
}

/// Create a new KNX stack.
///
/// The `state` parameter contains the unified device state including:
/// - Individual address, authentication keys, and other runtime configuration
/// - ETS-loaded tables (ADT, AST, COT, APP)
///
/// Use the device state constructor to create it:
/// - `SystemBDeviceState::new(&identity)` for fresh state
/// - `SystemBDeviceState::from_persisted(&identity, persisted)` to restore
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
        buffer_manager: RefCell::new(buffer_manager.dyn_buffer_manager()),
        app_service_channel: Channel::new(),
        comm_objs: RefCell::new(comm_objs),
        event_channel: PubSubChannel::new(),
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
    let (app_request_sender, app_request_receiver) =
        create_request_response_pair::<NoopRawMutex, _, 1>(unsafe { core::mem::transmute(&inner.app_service_channel) });

    // Create restart channel sender/receiver pair.
    // The sender goes to the Runner (passed to ApplicationLayer), receiver goes to Stack (for user code).
    let (restart_sender, restart_receiver) =
        create_request_response_pair::<NoopRawMutex, _, 1>(unsafe { core::mem::transmute(&inner.restart_channel) });

    // Initialize link layer resources using the builder
    let link_layer_resources = resources.link_layer_resources.write(link_layer_builder.create_resources());

    let stack = Stack {
        inner,
        interface_objects,
        app_request_sender: app_request_sender.into(),
        restart_receiver: restart_receiver.into(),
    };
    let runner = Runner {
        stack,
        interface_objects,
        app_request_receiver: app_request_receiver.into(),
        restart_sender: restart_sender.into(),
        link_layer_builder,
        link_layer_resources,
    };

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
        D::State: HasAddressTable + HasApplication + HasAssociationTable + HasCommunicationObjectTable,
        D::InterfaceObjects<'static>: HasDeviceObject,
    {
        // Initialize the run state machine at startup.
        // If the application is already loaded (from persistent storage), this will
        // transition it to RUNNING.
        self.stack.inner.state.app().borrow_mut().init_run_state();

        // Sync the DeviceControl user_stopped bit based on run state.
        let is_running = self.stack.inner.state.app().borrow().is_running();
        self.interface_objects.set_user_stopped(!is_running);

        // Create all the channels for layer to layer communication
        let ll_channel: Channel<NoopRawMutex, LayerOp<Buffer<'static>>, 1> = Channel::new();
        let nl_channel: Channel<NoopRawMutex, LayerOp<Buffer<'static>>, 1> = Channel::new();
        let tl_channel: Channel<NoopRawMutex, LayerOp<Buffer<'static>>, 1> = Channel::new();
        let al_channel: Channel<NoopRawMutex, LayerOp<Buffer<'static>>, 1> = Channel::new();

        // Create a network layer with reference to stack state and interface objects.
        // The routing count (hop count) for outgoing messages is read from the device object.
        let mut network_layer = NetworkLayer::new(
            &self.stack.inner.state,
            self.interface_objects,
            ll_channel.sender().into(),
            tl_channel.sender().into(),
        );

        // Create a transport layer
        let mut transport_layer = TransportLayer::<'_, D>::new(
            &self.stack.inner.buffer_manager,
            &self.stack.inner.state,
            nl_channel.sender().into(),
            al_channel.sender().into(),
            D::TL_STYLE,
        );

        // Create an application layer
        let mut application_layer = ApplicationLayer::<'_, D>::new(
            &self.stack.inner.buffer_manager,
            &self.stack.inner.state,
            &self.stack.inner.comm_objs,
            &self.stack.inner.hook_context,
            &self.stack.inner.event_channel,
            self.interface_objects,
            &self.stack.inner.memory_map,
            self.app_request_receiver,
            self.restart_sender,
            tl_channel.sender().into(),
        );

        // Build and run the link layer using the provided builder.
        // The StackContext provides both buffer management and property service
        // access, allowing the link layer to handle connection-oriented protocols
        // (e.g., KNX/IP Device Management) that need to read/write properties.
        let stack_context = StackContext {
            inner: self.stack.inner,
            interface_objects: self.interface_objects,
            al_sender: al_channel.sender().into(),
        };
        let ll_task = self.link_layer_builder.build_and_run(
            self.link_layer_resources,
            &stack_context,
            nl_channel.sender().into(),
            ll_channel.receiver(),
        );

        // Spawn and await all the upper layer tasks
        let nl_task = network_layer.process(nl_channel.receiver());
        let tl_task = transport_layer.process(tl_channel.receiver());
        let al_task = application_layer.process(al_channel.receiver());
        let tasks = embassy_futures::join::join4(ll_task, nl_task, tl_task, al_task);
        tasks.await;

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
        // Check if object is idle and set status atomically
        let accepted = self.inner.with_comm_objs(|co| {
            if !co.status(asap.index()).is_idle() {
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

        self.app_request_sender.request(ApplicationLayerService::GroupValueWriteRequest(asap.index())).await;
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
            if !co.status(asap).is_idle() {
                return false;
            }
            co.set_status(asap, ComObjectStatus::WriteRequest);
            true
        });

        if !accepted {
            return Err(UpdateObjectError::Busy);
        }

        self.app_request_sender.request(ApplicationLayerService::GroupValueWriteRequest(asap)).await;
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
            if !co.status(asap).is_idle() {
                return false;
            }
            co.set_status(asap, ComObjectStatus::ReadRequest);
            true
        });

        if !accepted {
            return Err(ReadObjectError::Busy);
        }

        self.app_request_sender.request(ApplicationLayerService::GroupValueReadRequest(asap)).await;
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
        // Check if object is idle and set status atomically
        let accepted = self.inner.with_comm_objs(|co| {
            if !co.status(asap.index()).is_idle() {
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
            self.app_request_sender.request(ApplicationLayerService::GroupValueReadRequest(asap.index())).await;
            return Ok(());
        };

        // Subscribe to events before sending the request to avoid race conditions
        let mut event_subscriber = self.events();

        // Send the read request
        self.app_request_sender.request(ApplicationLayerService::GroupValueReadRequest(asap.index())).await;

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
        let buffer = self.inner.buffer_manager.borrow_mut().alloc_from_slice(msg).await;
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
    /// When the stack receives an A_Restart message from the KNX bus, it validates the request
    /// and sends a [`restart::RestartRequest`] through this channel. User code should:
    ///
    /// 1. Call this method to receive the request
    /// 2. Execute the appropriate reset based on [`restart::EraseCode`]
    /// 3. Flush storage to persist any changes
    /// 4. Call [`Self::reply_to_restart`] to send the response
    /// 5. Trigger platform restart after the response is sent
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn handle_restart(stack: zweidraehte::Stack<'_, MyDevice>) {
    /// use zweidraehte::restart::{RestartRequest, RestartResponse, RestartError, EraseCode};
    ///
    /// loop {
    ///     let request = stack.receive_restart_request().await;
    ///
    ///     // Execute reset based on erase code
    ///     let response = match request.erase_code {
    ///         EraseCode::Basic | EraseCode::Confirmed => {
    ///             RestartResponse::success()
    ///         }
    ///         EraseCode::FactoryReset => {
    ///             // Perform factory reset
    ///             device_state.factory_reset();
    ///             RestartResponse::success()
    ///         }
    ///         _ => RestartResponse::error(RestartError::UnsupportedEraseCode),
    ///     };
    ///
    ///     // Send response back to stack (this will send A_Restart_Response if needed)
    ///     request.reply(response).await;
    ///
    ///     // Trigger platform restart via SystemControl trait
    ///     if response.error == RestartError::NoError {
    ///         embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
    ///         use platform::SystemControl;
    ///         let mut system = platform::LinuxSystem;
    ///         let Err(e) = system.restart().await;
    ///         panic!("Failed to restart: {:?}", e);
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn receive_restart_request(
        &self,
    ) -> Request<restart::RestartRequest, restart::RestartResponse> {
        self.restart_receiver.receive().await
    }

    /// Returns the current buffer pool usage as `(allocated, total)`.
    ///
    /// Useful for monitoring pool pressure and diagnosing potential deadlocks
    /// in production. When `allocated` approaches `total`, incoming allocations
    /// may block.
    pub fn buffer_pool_status(&self) -> (u8, u8) {
        let bm = self.inner.buffer_manager.borrow();
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
