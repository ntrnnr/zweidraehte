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
//!
//! # Table Objects
//!
//! Table objects share a common implementation via [`TableInterfaceObject<T, S>`] where:
//! - `T` is the underlying table type (implementing [`HasLoadStateMachine`])
//! - `S` is a marker type implementing [`TableObjectSpec`] that provides object-specific constants
//!
//! Type aliases are provided for convenience:
//! - [`AddressTableObject<T>`] = `TableInterfaceObject<T, AddressTableSpec>`
//! - [`AssociationTableObject<T>`] = `TableInterfaceObject<T, AssociationTableSpec>`
//! - [`GroupObjectTableObject<T>`] = `TableInterfaceObject<T, GroupObjectTableSpec>`

use core::cell::RefCell;
use core::marker::PhantomData;

use zweidraehte_proto::dpt::PDT_Control;

use crate::StackState;
use crate::device_model::{DeviceModelEvent, DeviceModelNotifier};
use crate::dpt::{
    DeviceControl, InterfaceObjectType, KNXVersion, PDT_Generic02, PDT_Generic04, PDT_Generic05, PDT_Generic06,
    PDT_Generic08, PDT_Generic10, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong, PDT_Version, ProgrammingMode,
    PropertyDataDefinition, RoutingCount,
};
use crate::objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadAction, RunEvent};

use super::{
    ArrayPropertyWithPrefixRead, ArrayPropertyWithPrefixWrite, InterfaceObject, PropertyAccess, PropertyDescriptor,
    PropertyError, PropertyRead, WriteResponse, pid,
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
    /// | 56 | Max APDU Length | PDT_UNSIGNED_INT | RO | (state-backed)
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
        pid::VERSION => version: PDT_Version, ReadOnly,
        pid::HARDWARE_TYPE => hardware_type: PDT_Generic06, ReadOnly,
        pid::DEVICE_DESCRIPTOR => device_descriptor: PDT_UnsignedInt, ReadOnly,
        // These are now stored directly in the DeviceObject with semantic types
        pid::ROUTING_COUNT => routing_count: RoutingCount, ReadWrite
    }
    state {
        // Programming mode is backed by StackState so both the application
        // layer (via property read/write) and the link layer (for discovery
        // responses) see the same value.
        pid::PROGMODE => {
            read: |s| [if s.is_programming_mode() { 0x01 } else { 0x00 }],
            write: |s, data| {
                s.set_programming_mode(data[0] != 0);
                Ok(())
            }
        }: ProgrammingMode, ReadWrite,

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

        // Max APDU length is read from StackState (may be constrained by link layer)
        pid::MAX_APDU_LENGTH => {
            read: |s| s.max_apdu_length().to_be_bytes(),
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

impl<'a, S: StackState> DeviceObject<'a, S> {
    /// Create a device object from a [`DeviceDescriptor`].
    ///
    /// Populates hardware type, mask version, and other static properties
    /// from the descriptor. Serial number, manufacturer ID, and max APDU
    /// length are read dynamically from the `StackState`.
    pub fn from_descriptor(state: &'a S, desc: &crate::ets::DeviceDescriptor) -> Self {
        let mut obj = Self::new(state);
        obj.hardware_type = PDT_Generic06::with_value(desc.hardware_type);
        obj.version = PDT_Version::with_value(KNXVersion::from_triplet(0, 0, 1));
        obj.device_descriptor = PDT_UnsignedInt::with_value(desc.mask_version.as_u16());
        obj
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
///   [`HasLoadStateMachine`] and [`HasRunStateMachine`])
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_device::objects::tables::app::Application;
/// use zweidraehte_device::objects::interface::ApplicationProgramObject;
///
/// // Create the underlying application table
/// let app_table = RefCell::new(Application::<()>::new());
///
/// // Create the interface object wrapping it (with allocation address 0x400)
/// let app_obj = ApplicationProgramObject::new(&app_table, 0x400);
/// ```
pub struct ApplicationProgramObject<'a, T: HasLoadStateMachine + HasRunStateMachine> {
    app: &'a RefCell<T>,
    /// Virtual address to assign during RelativeData allocation
    alloc_address: u32,
    program_version: PDT_Generic05,
    pei_type: PDT_UnsignedChar,
    /// Notifier for DeviceModel events (RSM lifecycle transitions).
    notifier: &'a dyn DeviceModelNotifier,
}

impl<'a, T: HasLoadStateMachine + HasRunStateMachine> ApplicationProgramObject<'a, T> {
    /// Create a new application program object wrapping an existing
    /// application table.
    ///
    /// # Arguments
    /// * `app` - Reference to the application table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation
    /// * `notifier` - Notification sink for DeviceModel lifecycle events
    pub fn new(app: &'a RefCell<T>, alloc_address: u32, notifier: &'a dyn DeviceModelNotifier) -> Self {
        Self {
            app,
            alloc_address,
            program_version: PDT_Generic05::default(),
            pei_type: PDT_UnsignedChar::default(),
            notifier,
        }
    }

    /// Create with specific program version and PEI type.
    pub fn with_info(
        app: &'a RefCell<T>,
        alloc_address: u32,
        program_version: PDT_Generic05,
        pei_type: PDT_UnsignedChar,
        notifier: &'a dyn DeviceModelNotifier,
    ) -> Self {
        Self { app, alloc_address, program_version, pei_type, notifier }
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
    fn property_descriptors() -> [PropertyDescriptor; 7] {
        [
            PropertyDescriptor::new(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::LOAD_STATE_CONTROL, PDT_Control::ID, 1, PropertyAccess::ReadWrite, 3, 3),
            PropertyDescriptor::new(pid::RUN_STATE_CONTROL, PDT_Control::ID, 1, PropertyAccess::ReadWrite, 3, 3),
            PropertyDescriptor::new(pid::TABLE_REFERENCE, PDT_UnsignedLong::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::PROGRAM_VERSION, PDT_Generic05::ID, 1, PropertyAccess::ReadWrite, 3, 3),
            PropertyDescriptor::new(pid::PEI_TYPE, PDT_UnsignedChar::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::MCB_TABLE, PDT_Generic08::ID, 1, PropertyAccess::ReadOnly, 3, 3),
        ]
    }
}

impl<'a, T: HasLoadStateMachine + HasRunStateMachine> InterfaceObject for ApplicationProgramObject<'a, T> {
    fn object_type(&self) -> InterfaceObjectType {
        InterfaceObjectType::ApplicationProgram
    }

    fn property_count(&self) -> u16 {
        7
    }

    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor> {
        Self::property_descriptors().get(prop_idx as usize).copied()
    }

    fn property_descriptor_by_id(&self, pid: u8) -> Option<(u16, PropertyDescriptor)> {
        Self::property_descriptors().iter().enumerate().find(|(_, d)| d.pid == pid).map(|(i, d)| (i as u16, *d))
    }

    fn read_property(&self, req: super::PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE => {
                let obj_type: u16 = InterfaceObjectType::ApplicationProgram.into();
                obj_type.to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::LOAD_STATE_CONTROL => self.app.borrow().read_lsm().read_property(req.start_idx, req.count, buf),
            super::pid::RUN_STATE_CONTROL => self.app.borrow().read_rsm().read_property(req.start_idx, req.count, buf),
            super::pid::TABLE_REFERENCE => {
                self.app.borrow().table_reference().to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::PROGRAM_VERSION => self.program_version.read_property(req.start_idx, req.count, buf),
            super::pid::PEI_TYPE => self.pei_type.read_property(req.start_idx, req.count, buf),
            super::pid::MCB_TABLE => {
                // Memory Control Block - 8 bytes (PDT_GENERIC_08)
                let app = self.app.borrow();
                app.mcb_bytes().read_property(req.start_idx, req.count, buf)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(&mut self, req: super::PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE | super::pid::PEI_TYPE => Err(PropertyError::WriteNotAllowed),
            super::pid::PROGRAM_VERSION => {
                // ETS writes the program version during programming
                if req.data.len() < 5 {
                    return Err(PropertyError::BufferTooSmall);
                }
                self.program_version = PDT_Generic05::from_slice(req.data);
                Ok(WriteResponse::Echo)
            }
            super::pid::LOAD_STATE_CONTROL => {
                let action = self.app.borrow_mut().write_lsm(req.data, Some(self.alloc_address));

                let run_action = match action {
                    LoadAction::LoadEnd => self.app.borrow_mut().handle_run_event(RunEvent::Loaded),
                    LoadAction::Unload => self.app.borrow_mut().handle_run_event(RunEvent::Unloaded),
                    _ => None,
                };

                if let Some(action) = run_action {
                    self.notifier.notify(DeviceModelEvent::RunAction(action));
                }

                Ok(WriteResponse::byte(self.app.borrow().read_lsm()[0]))
            }
            super::pid::RUN_STATE_CONTROL => {
                let run_action = self.app.borrow_mut().write_rsm(req.data);

                if let Some(action) = run_action {
                    self.notifier.notify(DeviceModelEvent::RunAction(action));
                }

                Ok(WriteResponse::byte(self.app.borrow().read_rsm()[0]))
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn property_element_count(&self, pid: u8) -> Result<u16, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE
            | super::pid::LOAD_STATE_CONTROL
            | super::pid::RUN_STATE_CONTROL
            | super::pid::TABLE_REFERENCE
            | super::pid::PROGRAM_VERSION
            | super::pid::PEI_TYPE
            | super::pid::MCB_TABLE => Ok(1),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }
}

// ============================================================================
// PEI Program Object (Object Type 5) - Interface Program
// ============================================================================

/// PEI (Physical External Interface) Program Object - Object Type 5.
///
/// This interface object is required by the KNX specification and ETS, but its
/// state transitions have no side effects on device operation. It exists purely
/// so that ETS can load/unload it during device programming without errors.
/// See [`PeiApplication`] for background on why PEI is vestigial.
///
/// The object exposes the same properties as [`ApplicationProgramObject`] but
/// reports a different object type (0x0005 instead of 0x0004).
///
/// # Properties
///
/// - OBJECT_TYPE (PID 1): Reports InterfaceObjectType::InterfaceProgram (5)
/// - LOAD_STATE_CONTROL (PID 5): Load state machine (no side effects)
/// - RUN_STATE_CONTROL (PID 6): Run state machine (no side effects)
/// - PROGRAM_VERSION (PID 13): Program version (always `[0; 5]` on modern devices)
pub struct PeiProgramObject<'a, T: HasLoadStateMachine + HasRunStateMachine> {
    pei: &'a RefCell<T>,
    /// Virtual address to assign during RelativeData allocation (typically 0 for PEI)
    alloc_address: u32,
    program_version: PDT_Generic05,
}

impl<'a, T: HasLoadStateMachine + HasRunStateMachine> PeiProgramObject<'a, T> {
    /// Create a new PEI program object.
    ///
    /// # Arguments
    /// * `pei` - Reference to the PEI application table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation (typically 0)
    /// * `program_version` - PEI program version (typically [0, 0, 0, 0, 0])
    pub fn new(pei: &'a RefCell<T>, alloc_address: u32, program_version: PDT_Generic05) -> Self {
        Self { pei, alloc_address, program_version }
    }

    /// Get the program version.
    pub fn program_version(&self) -> &PDT_Generic05 {
        &self.program_version
    }

    /// Get property descriptors for PEI program object.
    /// Note: PEI_TYPE (PID 14) is omitted since it's not used for the PEI object itself.
    fn property_descriptors() -> [PropertyDescriptor; 4] {
        [
            PropertyDescriptor::new(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::LOAD_STATE_CONTROL, PDT_Control::ID, 1, PropertyAccess::ReadWrite, 3, 0),
            PropertyDescriptor::new(pid::RUN_STATE_CONTROL, PDT_Control::ID, 1, PropertyAccess::ReadWrite, 3, 0),
            // PROGRAM_VERSION: ETS needs to write this during programming
            PropertyDescriptor::new(pid::PROGRAM_VERSION, PDT_Generic05::ID, 1, PropertyAccess::ReadWrite, 3, 0),
        ]
    }
}

impl<'a, T: HasLoadStateMachine + HasRunStateMachine> InterfaceObject for PeiProgramObject<'a, T> {
    fn object_type(&self) -> InterfaceObjectType {
        InterfaceObjectType::InterfaceProgram
    }

    fn property_count(&self) -> u16 {
        4
    }

    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor> {
        Self::property_descriptors().get(prop_idx as usize).copied()
    }

    fn property_descriptor_by_id(&self, pid: u8) -> Option<(u16, PropertyDescriptor)> {
        Self::property_descriptors().iter().enumerate().find(|(_, d)| d.pid == pid).map(|(i, d)| (i as u16, *d))
    }

    fn read_property(&self, req: super::PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE => {
                let obj_type: u16 = InterfaceObjectType::InterfaceProgram.into();
                obj_type.to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::LOAD_STATE_CONTROL => self.pei.borrow().read_lsm().read_property(req.start_idx, req.count, buf),
            super::pid::RUN_STATE_CONTROL => self.pei.borrow().read_rsm().read_property(req.start_idx, req.count, buf),
            super::pid::PROGRAM_VERSION => self.program_version.read_property(req.start_idx, req.count, buf),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(&mut self, req: super::PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE | super::pid::PROGRAM_VERSION => Err(PropertyError::WriteNotAllowed),
            super::pid::LOAD_STATE_CONTROL => {
                // Write the load event to the state machine, providing the allocation address
                self.pei.borrow_mut().write_lsm(req.data, Some(self.alloc_address));
                // Response contains the resulting load state (1 byte)
                Ok(WriteResponse::byte(self.pei.borrow().read_lsm()[0]))
            }
            super::pid::RUN_STATE_CONTROL => {
                // Write the run event to the state machine
                self.pei.borrow_mut().write_rsm(req.data);
                // Response contains the resulting run state (1 byte)
                Ok(WriteResponse::byte(self.pei.borrow().read_rsm()[0]))
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn property_element_count(&self, pid: u8) -> Result<u16, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE
            | super::pid::LOAD_STATE_CONTROL
            | super::pid::RUN_STATE_CONTROL
            | super::pid::PROGRAM_VERSION => Ok(1),
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
/// * `T` - The underlying table type (must implement `HasLoadStateMachine`)
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
pub struct TableInterfaceObject<'a, T: HasLoadStateMachine, S: TableObjectSpec> {
    table: &'a RefCell<T>,
    /// Virtual address to assign to this table during RelativeData allocation
    alloc_address: u32,
    _spec: PhantomData<S>,
}

impl<'a, T: HasLoadStateMachine, S: TableObjectSpec> TableInterfaceObject<'a, T, S> {
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
            PropertyDescriptor::new(pid::LOAD_STATE_CONTROL, PDT_Control::ID, 1, PropertyAccess::ReadWrite, 3, 0),
            PropertyDescriptor::new(pid::TABLE_REFERENCE, PDT_UnsignedLong::ID, 1, PropertyAccess::ReadOnly, 3, 3),
            PropertyDescriptor::new(pid::TABLE, S::TABLE_PDT, 0, PropertyAccess::ReadWrite, 3, 3), // max_elements set dynamically
            PropertyDescriptor::new(pid::MCB_TABLE, PDT_Generic08::ID, 1, PropertyAccess::ReadOnly, 3, 3),
        ]
    }
}

impl<'a, T: HasLoadStateMachine, S: TableObjectSpec> InterfaceObject for TableInterfaceObject<'a, T, S> {
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

    fn read_property(&self, req: super::PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE => {
                let obj_type: u16 = S::OBJECT_TYPE.into();
                obj_type.to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::LOAD_STATE_CONTROL => {
                self.table.borrow().read_lsm().read_property(req.start_idx, req.count, buf)
            }
            super::pid::TABLE_REFERENCE => {
                // Base address of the allocated table memory for memory read/write operations
                // Set during RelativeData allocation, cleared on unload
                self.table.borrow().table_reference().to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::TABLE => {
                // Array property - use appropriate trait based on table format
                let table = self.table.borrow();
                if S::HAS_COUNT_PREFIX {
                    table.data_ref().read_array_with_prefix(req.start_idx, req.count, S::ENTRY_SIZE, buf)
                } else {
                    use super::ArrayPropertyRead;
                    table.data_ref().read_array_property(req.start_idx, req.count, S::ENTRY_SIZE, buf)
                }
            }
            super::pid::MCB_TABLE => {
                // Memory Control Block - 8 bytes (PDT_GENERIC_08)
                // The MCB is populated during load (RelativeData segment) and CRC calculated on LoadEnd
                self.table.borrow().mcb_bytes().read_property(req.start_idx, req.count, buf)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(&mut self, req: super::PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE | super::pid::TABLE_REFERENCE | super::pid::MCB_TABLE => {
                Err(PropertyError::WriteNotAllowed)
            }
            super::pid::LOAD_STATE_CONTROL => {
                // Write the load event to the state machine, providing the allocation address
                self.table.borrow_mut().write_lsm(req.data, Some(self.alloc_address));
                // Response contains the resulting load state (1 byte), not the echoed data
                Ok(WriteResponse::byte(self.table.borrow().read_lsm()[0]))
            }
            super::pid::TABLE => {
                // Array property - use appropriate trait based on table format
                let mut table = self.table.borrow_mut();
                let _written = if S::HAS_COUNT_PREFIX {
                    table.data_ref_mut().write_array_with_prefix(req.start_idx, req.data, S::ENTRY_SIZE)?
                } else {
                    use super::ArrayPropertyWrite;
                    table.data_ref_mut().write_array_property(req.start_idx, req.data, S::ENTRY_SIZE)?
                };

                // Echo back written data
                Ok(WriteResponse::Echo)
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
/// Wraps an existing [`AddressTable`](crate::objects::tables::AddressTable) implementation to provide the
/// Interface Object API. Contains the group address table with entries
/// that can be looked up by TSAP.
pub type AddressTableObject<'a, T> = TableInterfaceObject<'a, T, AddressTableSpec>;

/// Association Table Object - Object Type 2
///
/// Wraps an existing [`AssociationTable`](crate::objects::tables::AssociationTable) implementation. Contains the
/// TSAP/ASAP mapping table for routing group communication.
pub type AssociationTableObject<'a, T> = TableInterfaceObject<'a, T, AssociationTableSpec>;

/// Group Object Table Object - Object Type 9
///
/// Wraps a [`CommunicationObjectTable`](crate::objects::tables::CommunicationObjectTable) implementation. Contains the
/// communication object descriptors (type + flags for each object).
pub type GroupObjectTableObject<'a, T> = TableInterfaceObject<'a, T, GroupObjectTableSpec>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::interface::PropertyReadRequest;
    use crate::objects::interface::PropertyWriteRequest;
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
        let len =
            obj.read_property(PropertyReadRequest { pid: pid::OBJECT_TYPE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // AddressTable = 1
    }

    #[test]
    fn test_address_table_load_state() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // Should start unloaded
        let mut buf = [0u8; 4];
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x00); // Unloaded

        // Start loading
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::StartLoading.into()],
        })
        .unwrap();

        let len = obj
            .read_property(PropertyReadRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
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
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x03]); // 3 entries

        // Read first entry (start_idx = 1)
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // GA 0/0/1

        // Read all 3 entries
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 3 }, &mut buf).unwrap();
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
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]); // 2 entries

        // Read first entry (4 bytes: TSAP + ASAP)
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 1 }, &mut buf).unwrap();
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
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]); // 2 entries

        // Read first entry (2 bytes: type + flags)
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0xDC]);

        // Read both entries
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 2 }, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0xDC, 0x08, 0x44]);
    }

    #[test]
    fn test_table_object_write_protection() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // OBJECT_TYPE should not be writable
        let result =
            obj.write_property(PropertyWriteRequest { pid: pid::OBJECT_TYPE, start_idx: 1, data: &[0x00, 0x00] });
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // TABLE_REFERENCE should not be writable
        let result = obj.write_property(PropertyWriteRequest {
            pid: pid::TABLE_REFERENCE,
            start_idx: 1,
            data: &[0x00, 0x00, 0x00, 0x00],
        });
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // MCB_TABLE should not be writable
        let result = obj.write_property(PropertyWriteRequest { pid: pid::MCB_TABLE, start_idx: 1, data: &[0x00; 8] });
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));
    }

    #[test]
    fn test_table_object_write_data() {
        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // Write count and entries via TABLE property
        obj.write_property(PropertyWriteRequest { pid: pid::TABLE, start_idx: 0, data: &[0x00, 0x02] }).unwrap(); // count = 2

        // Verify it was written
        let mut buf = [0u8; 10];
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]);
    }

    #[test]
    fn test_table_reference_after_load() {
        use crate::objects::tables::LoadEvent;

        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x1234);

        // TABLE_REFERENCE should be 0 initially (unloaded)
        let mut buf = [0u8; 10];
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x00]);

        // Start loading
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::StartLoading.into()],
        })
        .unwrap();

        // Allocate via RelativeData segment - this sets the TABLE_REFERENCE
        // Format: [event][segment_type][mcb_data...]
        // MCB data: [requested_memory_size:4][mode:1][fill:1][crc:2]
        let alloc_data = [
            LoadEvent::AdditionalLoadControls.into(),
            0x0B, // RelativeData segment
            0x00,
            0x00,
            0x00,
            0x08, // 8 bytes requested
            0x01, // mode = fill enabled
            0xFF, // fill byte
            0x00,
            0x00, // CRC placeholder
        ];
        obj.write_property(PropertyWriteRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, data: &alloc_data })
            .unwrap();

        // Now TABLE_REFERENCE should be set to 0x1234
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x12, 0x34]);

        // Complete loading
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::LoadCompleted.into()],
        })
        .unwrap();

        // TABLE_REFERENCE should still be 0x1234
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x12, 0x34]);

        // Unload - TABLE_REFERENCE should be cleared to 0
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::Unload.into()],
        })
        .unwrap();
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
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
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0xAB, 0xCD]);
    }
}
