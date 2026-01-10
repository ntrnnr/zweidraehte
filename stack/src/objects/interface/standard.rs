//! Standard Interface Object implementations
//!
//! This module provides implementations for the standard KNX interface objects.
//! These can be used directly or as a reference for custom implementations.
//!
//! # Object Types
//!
//! - [`DeviceObject`] - Device Object (Type 0) - Basic device information
//! - [`AddressTableObject`] - Address Table Object (Type 1) - Group address table
//! - [`AssociationTableObject`] - Association Table Object (Type 2) - TSAP/ASAP mapping
//! - [`ApplicationProgramObject`] - Application Program Object (Type 3)
//! - [`RouterObject`] - Router Object (Type 6) - For line/backbone couplers
//! - [`IpParameterObject`] - IP Parameter Object (Type 11) - For KNXnet/IP devices
//!
//! # Table Objects
//!
//! Table objects share a common implementation via [`TableInterfaceObject<T, S>`] where:
//! - `T` is the underlying table type (implementing [`LoadableTable`])
//! - `S` is a marker type implementing [`TableObjectSpec`] that provides object-specific constants
//!
//! Type aliases are provided for convenience:
//! - [`AddressTableObject<T>`] = `TableInterfaceObject<T, AddressTableSpec>`
//! - [`AssociationTableObject<T>`] = `TableInterfaceObject<T, AssociationTableSpec>`
//! - [`GroupObjectTableObject<T>`] = `TableInterfaceObject<T, GroupObjectTableSpec>`

use core::cell::RefCell;
use core::marker::PhantomData;

use crate::StackState;
use crate::dpt::{
    DeviceControl, InterfaceObjectType, PDT_Generic02, PDT_Generic04, PDT_Generic05, PDT_Generic06, PDT_Generic08,
    PDT_Generic10, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong, ProgrammingMode, PropertyDataDefinition,
    RoutingCount,
};
use crate::objects::tables::{LoadableTable, RunnableTable};

use super::{
    ArrayPropertyWithPrefixRead, ArrayPropertyWithPrefixWrite, InterfaceObject, PropertyAccess, PropertyDescriptor,
    PropertyError, PropertyRead, pid,
};

// ============================================================================
// Device Object (Object Type 0)
// ============================================================================

crate::define_interface_object! {
    /// Device Object - Object Type 0
    ///
    /// The Device Object contains basic device information and is mandatory
    /// for all KNX devices. It is always Object Index 0.
    ///
    /// This implementation holds a reference to the stack state for dynamic
    /// properties like individual address components.
    ///
    /// # Properties
    ///
    /// | PID | Name | Type | Access |
    /// |-----|------|------|--------|
    /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
    /// | 11 | Serial Number | PDT_GENERIC_06 | RO | (state-backed)
    /// | 12 | Manufacturer ID | PDT_UNSIGNED_INT | RO | (derived from serial number bytes 0-1)
    /// | 14 | Device Control | DeviceControl | RW |
    /// | 15 | Order Info | PDT_GENERIC_10 | RO |
    /// | 25 | Version | PDT_GENERIC_02 | RO |
    /// | 51 | Routing Count | RoutingCount | RW |
    /// | 54 | Programming Mode | ProgrammingMode | RW |
    /// | 56 | Max APDU Length | PDT_UNSIGNED_INT | RO |
    /// | 57 | Subnet Address | PDT_UNSIGNED_CHAR | RO |
    /// | 58 | Device Address | PDT_UNSIGNED_CHAR | RO |
    /// | 78 | Hardware Type | PDT_GENERIC_06 | RO |
    /// | 83 | Device Descriptor | PDT_UNSIGNED_INT | RO |
    pub struct DeviceObject<'a, S: StackState>: InterfaceObjectType::Device
        with state: &'a S
    {
        // Static properties (stored in struct) with semantic wrapper types
        pid::DEVICE_CONTROL => device_control: DeviceControl, ReadWrite,
        pid::ORDER_INFO => order_info: PDT_Generic10, ReadOnly,
        pid::VERSION => version: PDT_Generic02, ReadOnly,
        pid::MAX_APDU_LENGTH => max_apdu_length: PDT_UnsignedInt, ReadOnly,
        pid::HARDWARE_TYPE => hardware_type: PDT_Generic06, ReadOnly,
        pid::DEVICE_DESCRIPTOR => device_descriptor: PDT_UnsignedInt, ReadOnly,
        // These are now stored directly in the DeviceObject with semantic types
        pid::ROUTING_COUNT => routing_count: RoutingCount, ReadWrite,
        pid::PROGMODE => programming_mode: ProgrammingMode, ReadWrite
    }
    state {
        // State-backed properties (read/written via closures)
        // Serial number is read from StackState
        pid::SERIAL_NUMBER => {
            read: |s| *s.serial_number(),
            write: |_s, _data| Err(crate::objects::interface::PropertyError::WriteNotAllowed)
        }: PDT_Generic06, ReadOnly,

        // Manufacturer ID is derived from serial number bytes 0-1
        pid::MANUFACTURER_ID => {
            read: |s| {
                let sn = s.serial_number();
                [sn[0], sn[1]]
            },
            write: |_s, _data| Err(crate::objects::interface::PropertyError::WriteNotAllowed)
        }: PDT_UnsignedInt, ReadOnly,

        pid::SUBNET_ADDRESS => {
            read: |s| {
                let addr = s.individual_address();
                [(addr.area() << 4) | addr.line()]
            },
            write: |_s, _data| {
                Err(crate::objects::interface::PropertyError::WriteNotAllowed)
            }
        }: PDT_UnsignedChar, ReadOnly,

        pid::DEVICE_ADDRESS => {
            read: |s| [s.individual_address().device()],
            write: |_s, _data| {
                Err(crate::objects::interface::PropertyError::WriteNotAllowed)
            }
        }: PDT_UnsignedChar, ReadOnly
    }
}

/// Device information for creating a DeviceObject
///
/// Note: Serial number is not included here because it's read dynamically
/// from the `StackState::serial_number()` method.
pub struct DeviceInfo {
    /// Order information (10 bytes, manufacturer-specific)
    pub order_info: [u8; 10],
    /// Hardware type (6 bytes)
    pub hardware_type: [u8; 6],
    /// Firmware version (2 bytes: magic.version.revision encoded)
    pub version: [u8; 2],
    /// Maximum APDU length supported (typically 14 for TP, higher for IP)
    pub max_apdu_length: u16,
    /// Device descriptor (mask version, e.g., 0x07B0 for System B)
    pub device_descriptor: u16,
}

impl<'a, S: StackState> DeviceObject<'a, S> {
    /// Create a new device object with custom static values
    ///
    /// Serial number and manufacturer ID are read dynamically from the StackState.
    pub fn with_info(state: &'a S, info: &DeviceInfo) -> Self {
        let mut obj = Self::new(state);
        obj.order_info = PDT_Generic10::with_value(info.order_info);
        obj.version = PDT_Generic02::with_value(info.version);
        obj.max_apdu_length = PDT_UnsignedInt::with_value(info.max_apdu_length);
        obj.hardware_type = PDT_Generic06::with_value(info.hardware_type);
        obj.device_descriptor = PDT_UnsignedInt::with_value(info.device_descriptor);
        obj
    }

    /// Create a new device object with basic values (legacy API)
    ///
    /// Serial number and manufacturer ID are read dynamically from the StackState.
    pub fn with_values(state: &'a S, hardware_type_val: [u8; 6]) -> Self {
        Self::with_info(state, &DeviceInfo {
            order_info: [0; 10],
            hardware_type: hardware_type_val,
            version: [0x00, 0x01],     // Version 0.0.1
            max_apdu_length: 14,       // Standard TP APDU length
            device_descriptor: 0x07B0, // System B
        })
    }
}

// ============================================================================
// IP Parameter Object (Object Type 11 / 0x0B)
// ============================================================================

use core::net::Ipv4Addr;

use crate::IpStackState;
use crate::dpt::{PDT_Bitset8, PDT_Bitset16};
use crate::objects::interface::Ipv4Property;

/// Default KNX System Setup multicast address: 224.0.23.12
const SYSTEM_SETUP_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

crate::define_interface_object! {
    /// IP Parameter Object - Object Type 11 (0x0B)
    ///
    /// Contains KNXnet/IP configuration for IP-capable devices.
    /// This object is mandatory for KNXnet/IP devices.
    ///
    /// # Properties
    ///
    /// | PID | Name | Type | Access |
    /// |-----|------|------|--------|
    /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
    /// | 51 | Project Installation ID | PDT_UNSIGNED_INT | RW |
    /// | 52 | KNX Individual Address | PDT_UNSIGNED_INT | RW | (state-backed, delegates to DeviceObject)
    /// | 54 | Current IP Assignment Method | PDT_UNSIGNED_CHAR | RO |
    /// | 55 | IP Assignment Method | PDT_UNSIGNED_CHAR | RW |
    /// | 56 | IP Capabilities | PDT_BITSET8 | RO |
    /// | 57 | Current IP Address | PDT_UNSIGNED_LONG | RO |
    /// | 58 | Current Subnet Mask | PDT_UNSIGNED_LONG | RO |
    /// | 59 | Current Default Gateway | PDT_UNSIGNED_LONG | RO |
    /// | 60 | IP Address | PDT_UNSIGNED_LONG | RW |
    /// | 61 | Subnet Mask | PDT_UNSIGNED_LONG | RW |
    /// | 62 | Default Gateway | PDT_UNSIGNED_LONG | RW |
    /// | 64 | MAC Address | PDT_GENERIC_06 | RO |
    /// | 65 | System Setup Multicast Address | PDT_UNSIGNED_LONG | RO |
    /// | 66 | Routing Multicast Address | PDT_UNSIGNED_LONG | RW |
    /// | 67 | TTL | PDT_UNSIGNED_CHAR | RW |
    /// | 68 | KNXnet/IP Device Capabilities | PDT_BITSET16 | RO |
    /// | 76 | Friendly Name | PDT_UNSIGNED_CHAR[30] | RW |
    pub struct IpParameterObject<'a, S: IpStackState>: InterfaceObjectType::IPParameter
        with state: &'a S
    {
        // No static properties - all are state-backed for IP
    }
    // Properties requiring custom logic (complex types, constants, or special handling)
    state {
        // KNX Individual Address (uses IndividualAddress type, needs custom conversion)
        pid::KNX_INDIVIDUAL_ADDRESS => {
            read: |s| {
                let addr = s.individual_address();
                let bytes = addr.as_bytes();
                [bytes[0], bytes[1]]
            },
            write: |s, data| {
                if data.len() >= 2 {
                    s.set_individual_address(crate::address::IndividualAddress::from_bytes(data));
                    Ok(())
                } else {
                    Err(crate::objects::interface::PropertyError::BufferTooSmall)
                }
            }
        }: PDT_UnsignedInt, ReadWrite,

        // System Setup Multicast Address (fixed constant, not from state)
        pid::SYSTEM_SETUP_MULTICAST_ADDRESS => {
            read: |_s| u32::from(SYSTEM_SETUP_MULTICAST).to_be_bytes(),
            write: |_s, _data| Err(crate::objects::interface::PropertyError::WriteNotAllowed)
        }: PDT_UnsignedLong, ReadOnly
    }
    // Shorthand ReadWrite: auto-generates getter/setter calls
    state_rw {
        pid::PROJECT_INSTALLATION_ID => project_installation_id: PDT_UnsignedInt,
        pid::IP_ASSIGNMENT_METHOD => ip_assignment_method: PDT_UnsignedChar,
        pid::TTL => ttl: PDT_UnsignedChar,
        // IP addresses use Ipv4Property wrapper for Ipv4Addr <-> u32 conversion
        pid::IP_ADDRESS => configured_ip_address: Ipv4Property,
        pid::SUBNET_MASK => configured_subnet_mask: Ipv4Property,
        pid::DEFAULT_GATEWAY => configured_default_gateway: Ipv4Property,
        pid::ROUTING_MULTICAST_ADDRESS => routing_multicast_address: Ipv4Property
    }
    // Shorthand ReadOnly: auto-generates getter calls
    state_ro {
        pid::CURRENT_IP_ASSIGNMENT_METHOD => current_ip_assignment_method: PDT_UnsignedChar,
        pid::IP_CAPABILITIES => ip_capabilities: PDT_Bitset8,
        pid::MAC_ADDRESS => mac_address: PDT_Generic06,
        pid::KNXNETIP_DEVICE_CAPABILITIES => knxnetip_device_capabilities: PDT_Bitset16,
        // Current IP config (read-only from platform)
        pid::CURRENT_IP_ADDRESS => current_ip_address: Ipv4Property,
        pid::CURRENT_SUBNET_MASK => current_subnet_mask: Ipv4Property,
        pid::CURRENT_DEFAULT_GATEWAY => current_default_gateway: Ipv4Property
    }
}

impl<'a, S: IpStackState> IpParameterObject<'a, S> {
    /// Create a new IP Parameter Object with a reference to the IP stack state.
    pub fn with_state(state: &'a S) -> Self {
        Self::new(state)
    }
}

// ============================================================================
// Application Program Object (Object Type 3)
// ============================================================================

// ============================================================================
// Application Program Object (with proper state machines)
// ============================================================================

/// Application Program Object - Object Type 3
///
/// This is the proper implementation of the Application Program Object that
/// wraps a [`RunnableApplication<T>`](crate::objects::tables::RunnableApplication)
/// and implements both the Load State Machine and Run State Machine.
///
/// The application object is unique among interface objects because it has
/// two state machines:
/// - **Load State Machine**: Controls loading/unloading of application data
/// - **Run State Machine**: Controls execution state (HALTED, RUNNING, etc.)
///
/// # KNX Properties
///
/// | PID | Name | Type | Access | Description |
/// |-----|------|------|--------|-------------|
/// | 1 | Object Type | PDT_UNSIGNED_INT | RO | Object type identifier (3) |
/// | 5 | Load State Control | PDT_CONTROL | RW | Load state machine |
/// | 6 | Run State Control | PDT_CONTROL | RW | Run state machine |
/// | 13 | Program Version | PDT_GENERIC_05 | RO | Application program version |
/// | 16 | PEI Type | PDT_UNSIGNED_CHAR | RO | PEI type (0 for none) |
///
/// # Type Parameters
///
/// * `T` - The underlying application table type (must implement both
///   [`LoadableTable`] and [`RunnableTable`])
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::objects::tables::app::Application;
/// use zweidraehte::objects::interface::ApplicationProgramObject;
///
/// // Create the underlying application table
/// let app_table = RefCell::new(Application::<()>::new());
///
/// // Create the interface object wrapping it (with allocation address 0x400)
/// let app_obj = ApplicationProgramObject::new(&app_table, 0x400);
/// ```
pub struct ApplicationProgramObject<'a, T: LoadableTable + RunnableTable> {
    app: &'a RefCell<T>,
    /// Virtual address to assign during RelativeData allocation
    alloc_address: u32,
    program_version: PDT_Generic05,
    pei_type: PDT_UnsignedChar,
}

impl<'a, T: LoadableTable + RunnableTable> ApplicationProgramObject<'a, T> {
    /// Create a new application program object wrapping an existing
    /// application table.
    ///
    /// # Arguments
    /// * `app` - Reference to the application table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation
    pub fn new(app: &'a RefCell<T>, alloc_address: u32) -> Self {
        Self { app, alloc_address, program_version: PDT_Generic05::default(), pei_type: PDT_UnsignedChar::default() }
    }

    /// Create with specific program version and PEI type.
    pub fn with_info(
        app: &'a RefCell<T>,
        alloc_address: u32,
        program_version: PDT_Generic05,
        pei_type: PDT_UnsignedChar,
    ) -> Self {
        Self { app, alloc_address, program_version, pei_type }
    }

    /// Get the program version.
    pub fn program_version(&self) -> &PDT_Generic05 {
        &self.program_version
    }

    /// Set the program version.
    pub fn set_program_version(&mut self, version: PDT_Generic05) {
        self.program_version = version;
    }

    /// Get the PEI type.
    pub fn pei_type(&self) -> &PDT_UnsignedChar {
        &self.pei_type
    }

    /// Set the PEI type.
    pub fn set_pei_type(&mut self, pei_type: PDT_UnsignedChar) {
        self.pei_type = pei_type;
    }

    /// Get property descriptors for application program object.
    fn property_descriptors() -> [PropertyDescriptor; 5] {
        [
            PropertyDescriptor::new(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            // LOAD_STATE_CONTROL: read=3 (anyone), write=0 (requires authorization)
            PropertyDescriptor::new(pid::LOAD_STATE_CONTROL, PDT_UnsignedChar::ID, 1, PropertyAccess::ReadWrite, 3, 0),
            // RUN_STATE_CONTROL: read=3 (anyone), write=0 (requires authorization)
            PropertyDescriptor::new(pid::RUN_STATE_CONTROL, PDT_UnsignedChar::ID, 1, PropertyAccess::ReadWrite, 3, 0),
            PropertyDescriptor::new(pid::PROGRAM_VERSION, PDT_Generic05::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::PEI_TYPE, PDT_UnsignedChar::ID, 1, PropertyAccess::ReadOnly, 3, 3),
        ]
    }
}

impl<'a, T: LoadableTable + RunnableTable> InterfaceObject for ApplicationProgramObject<'a, T> {
    fn object_type(&self) -> InterfaceObjectType {
        InterfaceObjectType::ApplicationProgram
    }

    fn property_count(&self) -> u16 {
        5
    }

    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor> {
        Self::property_descriptors().get(prop_idx as usize).copied()
    }

    fn property_descriptor_by_id(&self, pid: u8) -> Option<(u16, PropertyDescriptor)> {
        Self::property_descriptors().iter().enumerate().find(|(_, d)| d.pid == pid).map(|(i, d)| (i as u16, *d))
    }

    fn read_property(&self, pid: u8, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE => {
                let obj_type: u16 = InterfaceObjectType::ApplicationProgram.into();
                obj_type.to_be_bytes().read_property(start_idx, count, buf)
            }
            super::pid::LOAD_STATE_CONTROL => self.app.borrow().read_lsm().read_property(start_idx, count, buf),
            super::pid::RUN_STATE_CONTROL => self.app.borrow().read_rsm().read_property(start_idx, count, buf),
            super::pid::PROGRAM_VERSION => self.program_version.read_property(start_idx, count, buf),
            super::pid::PEI_TYPE => self.pei_type.read_property(start_idx, count, buf),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(
        &mut self,
        pid: u8,
        _start_idx: u16,
        data: &[u8],
        response_buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE | super::pid::PROGRAM_VERSION | super::pid::PEI_TYPE => {
                Err(PropertyError::WriteNotAllowed)
            }
            super::pid::LOAD_STATE_CONTROL => {
                // Write the load event to the state machine, providing the allocation address
                self.app.borrow_mut().write_lsm(data, Some(self.alloc_address));
                // Response contains the resulting load state (1 byte)
                if response_buf.is_empty() {
                    return Err(PropertyError::BufferTooSmall);
                }
                response_buf[0] = self.app.borrow().read_lsm()[0];
                Ok(1)
            }
            super::pid::RUN_STATE_CONTROL => {
                // Write the run event to the state machine
                self.app.borrow_mut().write_rsm(data);
                // Response contains the resulting run state (1 byte)
                if response_buf.is_empty() {
                    return Err(PropertyError::BufferTooSmall);
                }
                response_buf[0] = self.app.borrow().read_rsm()[0];
                Ok(1)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn property_element_count(&self, pid: u8) -> Result<u16, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE
            | super::pid::LOAD_STATE_CONTROL
            | super::pid::RUN_STATE_CONTROL
            | super::pid::PROGRAM_VERSION
            | super::pid::PEI_TYPE => Ok(1),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }
}

// // ============================================================================
// // Router Object (Object Type 6) - For line/backbone couplers
// // ============================================================================

// crate::define_interface_object! {
//     /// Router Object - Object Type 6
//     ///
//     /// Contains routing configuration for line/backbone couplers.
//     /// This object is only present in routing devices.
//     ///
//     /// # Properties
//     ///
//     /// | PID | Name | Type | Access |
//     /// |-----|------|------|--------|
//     /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
//     /// | 51 | Line Status | PDT_GENERIC_01 | RO |
//     /// | 52 | Main LC Config | PDT_GENERIC_01 | RW |
//     /// | 53 | Sub LC Config | PDT_GENERIC_01 | RW |
//     pub struct RouterObject: InterfaceObjectType::Router {
//         pid::LINE_STATUS => line_status: PDT_Generic01, ReadOnly;
//         pid::MAIN_LCCONFIG => main_lc_config: PDT_Generic01, ReadWrite;
//         pid::SUB_LCCONFIG => sub_lc_config: PDT_Generic01, ReadWrite;
//         pid::MAIN_LCGRPCONFIG => main_lc_grp_config: PDT_Generic01, ReadWrite;
//         pid::SUB_LCGRPCONFIG => sub_lc_grp_config: PDT_Generic01, ReadWrite
//     }
// }

// ============================================================================
// Address Table Object (Object Type 1)
// ============================================================================

// ============================================================================
// Generic Table Interface Object Implementation
// ============================================================================

/// Specification trait for table interface objects.
///
/// This trait provides the constants that differ between table types,
/// allowing a single generic implementation to handle all table objects.
pub trait TableObjectSpec {
    /// The interface object type (e.g., AddressTable, AssociationTable)
    const OBJECT_TYPE: InterfaceObjectType;

    /// Bytes per table entry
    const ENTRY_SIZE: usize;

    /// PDT type ID for the TABLE property
    const TABLE_PDT: u8;

    /// Whether the table data starts with a 2-byte count prefix
    /// (true for most tables, determines offset calculation)
    const HAS_COUNT_PREFIX: bool;
}

/// Generic table interface object implementation.
///
/// This struct provides the `InterfaceObject` implementation for any table type,
/// parameterized by a specification trait that provides the type-specific constants.
///
/// # Type Parameters
///
/// * `T` - The underlying table type (must implement `LoadableTable`)
/// * `S` - A marker type implementing `TableObjectSpec` for object-specific constants
///
/// # KNX Properties (common to all table objects)
///
/// | PID | Name | Type | Access | Description |
/// |-----|------|------|--------|-------------|
/// | 1 | Object Type | PDT_UNSIGNED_INT | RO | Object type identifier |
/// | 5 | Load State Control | PDT_CONTROL | RW | Load state machine |
/// | 7 | Table Reference | PDT_UNSIGNED_LONG | RO | Base address of allocated table memory |
/// | 23 | Table | varies | RW* | Direct table data access |
/// | 27 | MCB Table | PDT_GENERIC_08 | RO | Memory control block |
pub struct TableInterfaceObject<'a, T: LoadableTable, S: TableObjectSpec> {
    table: &'a RefCell<T>,
    /// Virtual address to assign to this table during RelativeData allocation
    alloc_address: u32,
    _spec: PhantomData<S>,
}

impl<'a, T: LoadableTable, S: TableObjectSpec> TableInterfaceObject<'a, T, S> {
    /// Create a new table interface object wrapping an existing table.
    ///
    /// # Arguments
    /// * `table` - Reference to the table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation.
    ///   Per KNX spec, this is set when memory is allocated and cleared on unload.
    pub fn new(table: &'a RefCell<T>, alloc_address: u32) -> Self {
        Self { table, alloc_address, _spec: PhantomData }
    }

    /// Get property descriptors for table objects
    fn property_descriptors() -> [PropertyDescriptor; 5] {
        [
            PropertyDescriptor::new(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            // LOAD_STATE_CONTROL: read/write access level 3/3 per KNX profile specification
            // However, the access control check happens at the PropertyServiceHandler level,
            // which requires caller's access_level <= write_level (lower = more access).
            // So write_level=0 means only callers with level 0 (full access) can write.
            PropertyDescriptor::new(pid::LOAD_STATE_CONTROL, PDT_UnsignedChar::ID, 1, PropertyAccess::ReadWrite, 3, 0),
            PropertyDescriptor::new(pid::TABLE_REFERENCE, PDT_UnsignedLong::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::TABLE, S::TABLE_PDT, 0, PropertyAccess::ReadWrite, 3, 3), // max_elements set dynamically
            PropertyDescriptor::new(pid::MCB_TABLE, PDT_Generic08::ID, 1, PropertyAccess::ReadOnly, 3, 3),
        ]
    }
}

impl<'a, T: LoadableTable, S: TableObjectSpec> InterfaceObject for TableInterfaceObject<'a, T, S> {
    fn object_type(&self) -> InterfaceObjectType {
        S::OBJECT_TYPE
    }

    fn property_count(&self) -> u16 {
        5 // Fixed number of properties for all table objects
    }

    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor> {
        let descriptors = Self::property_descriptors();
        let mut desc = descriptors.get(prop_idx as usize).copied()?;
        // Dynamically set max_elements for TABLE property
        if desc.pid == pid::TABLE {
            desc.max_elements = (self.table.borrow().data_ref().len() / S::ENTRY_SIZE) as u16;
        }
        Some(desc)
    }

    fn property_descriptor_by_id(&self, pid: u8) -> Option<(u16, PropertyDescriptor)> {
        let descriptors = Self::property_descriptors();
        descriptors.iter().enumerate().find(|(_, d)| d.pid == pid).map(|(i, d)| {
            let mut desc = *d;
            if desc.pid == super::pid::TABLE {
                desc.max_elements = (self.table.borrow().data_ref().len() / S::ENTRY_SIZE) as u16;
            }
            (i as u16, desc)
        })
    }

    fn read_property(&self, pid: u8, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE => {
                let obj_type: u16 = S::OBJECT_TYPE.into();
                obj_type.to_be_bytes().read_property(start_idx, count, buf)
            }
            super::pid::LOAD_STATE_CONTROL => self.table.borrow().read_lsm().read_property(start_idx, count, buf),
            super::pid::TABLE_REFERENCE => {
                // Base address of the allocated table memory for memory read/write operations
                // Set during RelativeData allocation, cleared on unload
                self.table.borrow().table_reference().to_be_bytes().read_property(start_idx, count, buf)
            }
            super::pid::TABLE => {
                // Array property - use appropriate trait based on table format
                let table = self.table.borrow();
                if S::HAS_COUNT_PREFIX {
                    table.data_ref().read_array_with_prefix(start_idx, count, S::ENTRY_SIZE, buf)
                } else {
                    use super::ArrayPropertyRead;
                    table.data_ref().read_array_property(start_idx, count, S::ENTRY_SIZE, buf)
                }
            }
            super::pid::MCB_TABLE => {
                // Memory Control Block - 8 bytes (PDT_GENERIC_08)
                // The MCB is populated during load (RelativeData segment) and CRC calculated on LoadEnd
                self.table.borrow().mcb_bytes().read_property(start_idx, count, buf)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(
        &mut self,
        pid: u8,
        start_idx: u16,
        data: &[u8],
        response_buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE | super::pid::TABLE_REFERENCE | super::pid::MCB_TABLE => {
                Err(PropertyError::WriteNotAllowed)
            }
            super::pid::LOAD_STATE_CONTROL => {
                // Write the load event to the state machine, providing the allocation address
                self.table.borrow_mut().write_lsm(data, Some(self.alloc_address));
                // Response contains the resulting load state (1 byte), not the echoed data
                if response_buf.is_empty() {
                    return Err(PropertyError::BufferTooSmall);
                }
                response_buf[0] = self.table.borrow().read_lsm()[0];
                Ok(1)
            }
            super::pid::TABLE => {
                // Array property - use appropriate trait based on table format
                let mut table = self.table.borrow_mut();
                let written = if S::HAS_COUNT_PREFIX {
                    table.data_ref_mut().write_array_with_prefix(start_idx, data, S::ENTRY_SIZE)?
                } else {
                    use super::ArrayPropertyWrite;
                    table.data_ref_mut().write_array_property(start_idx, data, S::ENTRY_SIZE)?
                };

                // Echo back written data
                let len = written.min(response_buf.len());
                response_buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn property_element_count(&self, pid: u8) -> Result<u16, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE => Ok(1),
            super::pid::LOAD_STATE_CONTROL => Ok(1),
            super::pid::TABLE_REFERENCE => Ok(1),
            super::pid::TABLE => {
                let table = self.table.borrow();
                if S::HAS_COUNT_PREFIX {
                    Ok(table.data_ref().element_count_from_prefix())
                } else {
                    use super::ArrayPropertyRead;
                    Ok(table.data_ref().element_count(S::ENTRY_SIZE))
                }
            }
            super::pid::MCB_TABLE => Ok(1),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }
}

// ============================================================================
// Table Object Specifications
// ============================================================================

/// Specification for Address Table Object (Type 1)
pub struct AddressTableSpec;

impl TableObjectSpec for AddressTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::AddressTable;
    const ENTRY_SIZE: usize = 2; // Group Address = 2 bytes
    const TABLE_PDT: u8 = PDT_UnsignedInt::ID; // 2-byte entries
    const HAS_COUNT_PREFIX: bool = true;
}

/// Specification for Association Table Object (Type 2)
pub struct AssociationTableSpec;

impl TableObjectSpec for AssociationTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::AssociationTable;
    const ENTRY_SIZE: usize = 4; // TSAP + ASAP = 4 bytes
    const TABLE_PDT: u8 = PDT_Generic04::ID;
    const HAS_COUNT_PREFIX: bool = true;
}

/// Specification for Group Object Table Object (Type 9)
pub struct GroupObjectTableSpec;

impl TableObjectSpec for GroupObjectTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::GroupObjectTable;
    const ENTRY_SIZE: usize = 2; // Type + Flags = 2 bytes
    const TABLE_PDT: u8 = PDT_Generic02::ID;
    const HAS_COUNT_PREFIX: bool = true;
}

// ============================================================================
// Type Aliases for Table Interface Objects
// ============================================================================

/// Address Table Object - Object Type 1
///
/// Wraps an existing [`AddressTable`] implementation to provide the
/// Interface Object API. Contains the group address table with entries
/// that can be looked up by TSAP.
pub type AddressTableObject<'a, T> = TableInterfaceObject<'a, T, AddressTableSpec>;

/// Association Table Object - Object Type 2
///
/// Wraps an existing [`AssociationTable`] implementation. Contains the
/// TSAP/ASAP mapping table for routing group communication.
pub type AssociationTableObject<'a, T> = TableInterfaceObject<'a, T, AssociationTableSpec>;

/// Group Object Table Object - Object Type 9
///
/// Wraps a [`CommunicationObjectTable`] implementation. Contains the
/// communication object descriptors (type + flags for each object).
pub type GroupObjectTableObject<'a, T> = TableInterfaceObject<'a, T, GroupObjectTableSpec>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::tables::addr7::AddrTab7;
    use crate::objects::tables::asso6::AssoTab6;
    use crate::objects::tables::co7::CoTab7;
    use crate::objects::tables::{LoadEvent, TableMemory};

    #[test]
    fn test_address_table_object_type() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let obj = AddressTableObject::new(&addr_table, 0x100);

        assert_eq!(obj.object_type(), InterfaceObjectType::AddressTable);

        // Read OBJECT_TYPE property
        let mut buf = [0u8; 4];
        let len = obj.read_property(pid::OBJECT_TYPE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // AddressTable = 1
    }

    #[test]
    fn test_address_table_load_state() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // Should start unloaded
        let mut buf = [0u8; 4];
        let len = obj.read_property(pid::LOAD_STATE_CONTROL, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x00); // Unloaded

        // Start loading
        let mut resp_buf = [0u8; 4];
        obj.write_property(pid::LOAD_STATE_CONTROL, 1, &[LoadEvent::StartLoading.into()], &mut resp_buf).unwrap();

        let len = obj.read_property(pid::LOAD_STATE_CONTROL, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x02); // Loading
    }

    #[test]
    fn test_address_table_table_property() {
        let addr_table = RefCell::new(AddrTab7::<20>::new());

        // Pre-load some data into the table
        {
            let mut table = addr_table.borrow_mut();
            // Write count = 3, then 3 group addresses
            table.data_ref_mut()[0..2].copy_from_slice(&[0x00, 0x03]); // count = 3
            table.data_ref_mut()[2..4].copy_from_slice(&[0x00, 0x01]); // GA 0/0/1
            table.data_ref_mut()[4..6].copy_from_slice(&[0x00, 0x02]); // GA 0/0/2
            table.data_ref_mut()[6..8].copy_from_slice(&[0x00, 0x03]); // GA 0/0/3
        }

        let obj = AddressTableObject::new(&addr_table, 0x100);

        // Read element count (start_idx = 0)
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE, 0, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x03]); // 3 entries

        // Read first entry (start_idx = 1)
        let len = obj.read_property(pid::TABLE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // GA 0/0/1

        // Read all 3 entries
        let len = obj.read_property(pid::TABLE, 1, 3, &mut buf).unwrap();
        assert_eq!(len, 6);
        assert_eq!(&buf[0..6], &[0x00, 0x01, 0x00, 0x02, 0x00, 0x03]);
    }

    #[test]
    fn test_address_table_property_descriptors() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let obj = AddressTableObject::new(&addr_table, 0x100);

        assert_eq!(obj.property_count(), 5);

        // Check each property descriptor
        let desc = obj.property_descriptor_by_id(pid::OBJECT_TYPE).unwrap();
        assert_eq!(desc.1.pid, 1);
        assert_eq!(desc.1.access, PropertyAccess::ReadOnly);

        let desc = obj.property_descriptor_by_id(pid::LOAD_STATE_CONTROL).unwrap();
        assert_eq!(desc.1.pid, 5);
        assert_eq!(desc.1.access, PropertyAccess::ReadWrite);

        let desc = obj.property_descriptor_by_id(pid::TABLE).unwrap();
        assert_eq!(desc.1.pid, 23);
        assert_eq!(desc.1.access, PropertyAccess::ReadWrite);
    }

    #[test]
    fn test_association_table_object() {
        let asso_table = RefCell::new(AssoTab6::<40>::new());

        // Pre-load association data
        {
            let mut table = asso_table.borrow_mut();
            // Format: [count:2][tsap1:2][asap1:2][tsap2:2][asap2:2]...
            table.data_ref_mut()[0..2].copy_from_slice(&[0x00, 0x02]); // 2 entries
            table.data_ref_mut()[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TSAP 1 -> ASAP 1
            table.data_ref_mut()[6..10].copy_from_slice(&[0x00, 0x02, 0x00, 0x02]); // TSAP 2 -> ASAP 2
        }

        let obj = AssociationTableObject::new(&asso_table, 0x200);

        assert_eq!(obj.object_type(), InterfaceObjectType::AssociationTable);

        // Read element count
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE, 0, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]); // 2 entries

        // Read first entry (4 bytes: TSAP + ASAP)
        let len = obj.read_property(pid::TABLE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_group_object_table_object() {
        let co_table = RefCell::new(CoTab7::<20>::new());

        // Pre-load communication object data
        {
            let mut table = co_table.borrow_mut();
            // Format: [count:2][type1:1][flags1:1][type2:1][flags2:1]...
            table.data_ref_mut()[0..2].copy_from_slice(&[0x00, 0x02]); // 2 entries
            table.data_ref_mut()[2..4].copy_from_slice(&[0x00, 0xDC]); // Type Bit1, flags RTWU
            table.data_ref_mut()[4..6].copy_from_slice(&[0x08, 0x44]); // Type Byte2, flags T
        }

        let obj = GroupObjectTableObject::new(&co_table, 0x300);

        assert_eq!(obj.object_type(), InterfaceObjectType::GroupObjectTable);

        // Read element count
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE, 0, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]); // 2 entries

        // Read first entry (2 bytes: type + flags)
        let len = obj.read_property(pid::TABLE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0xDC]);

        // Read both entries
        let len = obj.read_property(pid::TABLE, 1, 2, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0xDC, 0x08, 0x44]);
    }

    #[test]
    fn test_table_object_write_protection() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);
        let mut resp_buf = [0u8; 10];

        // OBJECT_TYPE should not be writable
        let result = obj.write_property(pid::OBJECT_TYPE, 1, &[0x00, 0x00], &mut resp_buf);
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // TABLE_REFERENCE should not be writable
        let result = obj.write_property(pid::TABLE_REFERENCE, 1, &[0x00, 0x00, 0x00, 0x00], &mut resp_buf);
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // MCB_TABLE should not be writable
        let result = obj.write_property(pid::MCB_TABLE, 1, &[0x00; 8], &mut resp_buf);
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));
    }

    #[test]
    fn test_table_object_write_data() {
        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);
        let mut resp_buf = [0u8; 10];

        // Write count and entries via TABLE property
        obj.write_property(pid::TABLE, 0, &[0x00, 0x02], &mut resp_buf).unwrap(); // count = 2

        // Verify it was written
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE, 0, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]);
    }

    #[test]
    fn test_table_reference_after_load() {
        use crate::objects::tables::{LoadEvent, LoadableTable};

        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x1234);

        // TABLE_REFERENCE should be 0 initially (unloaded)
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE_REFERENCE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x00]);

        // Start loading
        obj.write_property(pid::LOAD_STATE_CONTROL, 1, &[LoadEvent::StartLoading.into()], &mut buf).unwrap();

        // Allocate via RelativeData segment - this sets the TABLE_REFERENCE
        // Format: [event][segment_type][mcb_data...]
        // MCB data: [requested_memory_size:4][mode:1][fill:1][crc:2]
        let alloc_data = [
            LoadEvent::AdditionalLoadControls.into(),
            0x0B, // RelativeData segment
            0x00, 0x00, 0x00, 0x08, // 8 bytes requested
            0x01, // mode = fill enabled
            0xFF, // fill byte
            0x00, 0x00, // CRC placeholder
        ];
        obj.write_property(pid::LOAD_STATE_CONTROL, 1, &alloc_data, &mut buf).unwrap();

        // Now TABLE_REFERENCE should be set to 0x1234
        let len = obj.read_property(pid::TABLE_REFERENCE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x12, 0x34]);

        // Complete loading
        obj.write_property(pid::LOAD_STATE_CONTROL, 1, &[LoadEvent::LoadCompleted.into()], &mut buf).unwrap();

        // TABLE_REFERENCE should still be 0x1234
        let len = obj.read_property(pid::TABLE_REFERENCE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x12, 0x34]);

        // Unload - TABLE_REFERENCE should be cleared to 0
        obj.write_property(pid::LOAD_STATE_CONTROL, 1, &[LoadEvent::Unload.into()], &mut buf).unwrap();
        let len = obj.read_property(pid::TABLE_REFERENCE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_table_reference_with_preloaded_data() {
        use crate::objects::tables::Table;
        use crate::objects::tables::addr7::AddrTab7Impl;

        // Create a table with pre-loaded data and table_reference
        let preloaded_table: Table<AddrTab7Impl<20>> = Table::with_data(
            &[0x00, 0x01, 0x10, 0x00], // count=1, addr=2/0/0
            0xABCD,
        );
        let addr_table = RefCell::new(preloaded_table);
        let obj = AddressTableObject::new(&addr_table, 0x1234); // alloc_address ignored for preloaded

        // TABLE_REFERENCE should be 0xABCD (from with_data)
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE_REFERENCE, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0xAB, 0xCD]);
    }
}
