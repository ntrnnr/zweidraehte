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

use crate::dpt::{
    InterfaceObjectType, PDT_Generic01, PDT_Generic02, PDT_Generic05, PDT_Generic06,
    PDT_UnsignedChar, PDT_UnsignedInt, PropertyDataDefinition,
};
use crate::objects::tables::LoadableTable;

use super::{pid, InterfaceObject, PropertyAccess, PropertyDescriptor, PropertyError};

// ============================================================================
// Device Object (Object Type 0)
// ============================================================================

crate::define_interface_object! {
    /// Device Object - Object Type 0
    ///
    /// The Device Object contains basic device information and is mandatory
    /// for all KNX devices. It is always Object Index 0.
    ///
    /// # Properties
    ///
    /// | PID | Name | Type | Access |
    /// |-----|------|------|--------|
    /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
    /// | 11 | Serial Number | PDT_GENERIC_06 | RW |
    /// | 12 | Manufacturer ID | PDT_UNSIGNED_INT | RO |
    /// | 14 | Device Control | PDT_GENERIC_01 | RW |
    /// | 78 | Hardware Type | PDT_GENERIC_06 | RO |
    pub struct DeviceObject: InterfaceObjectType::Device {
        pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
        pid::MANUFACTURER_ID => manufacturer_id: PDT_UnsignedInt, ReadOnly;
        pid::DEVICE_CONTROL => device_control: PDT_Generic01, ReadWrite;
        pid::HARDWARE_TYPE => hardware_type: PDT_Generic06, ReadOnly
    }
}

// ============================================================================
// Application Program Object (Object Type 3)
// ============================================================================

crate::define_interface_object! {
    /// Application Program Object - Object Type 3
    ///
    /// Contains information about the loaded application program.
    ///
    /// # Properties
    ///
    /// | PID | Name | Type | Access |
    /// |-----|------|------|--------|
    /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
    /// | 5 | Load State Control | PDT_UNSIGNED_CHAR | RW |
    /// | 6 | Run State Control | PDT_UNSIGNED_CHAR | RW |
    /// | 13 | Program Version | PDT_GENERIC_05 | RO |
    /// | 16 | PEI Type | PDT_UNSIGNED_CHAR | RO |
    pub struct ApplicationProgramObject: InterfaceObjectType::ApplicationProgram {
        pid::LOAD_STATE_CONTROL => load_state: PDT_UnsignedChar, ReadWrite;
        pid::RUN_STATE_CONTROL => run_state: PDT_UnsignedChar, ReadWrite;
        pid::PROGRAM_VERSION => program_version: PDT_Generic05, ReadOnly;
        pid::PEI_TYPE => pei_type: PDT_UnsignedChar, ReadOnly
    }
}

// ============================================================================
// Router Object (Object Type 6) - For line/backbone couplers
// ============================================================================

crate::define_interface_object! {
    /// Router Object - Object Type 6
    ///
    /// Contains routing configuration for line/backbone couplers.
    /// This object is only present in routing devices.
    ///
    /// # Properties
    ///
    /// | PID | Name | Type | Access |
    /// |-----|------|------|--------|
    /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
    /// | 51 | Line Status | PDT_GENERIC_01 | RO |
    /// | 52 | Main LC Config | PDT_GENERIC_01 | RW |
    /// | 53 | Sub LC Config | PDT_GENERIC_01 | RW |
    pub struct RouterObject: InterfaceObjectType::Router {
        pid::LINE_STATUS => line_status: PDT_Generic01, ReadOnly;
        pid::MAIN_LCCONFIG => main_lc_config: PDT_Generic01, ReadWrite;
        pid::SUB_LCCONFIG => sub_lc_config: PDT_Generic01, ReadWrite;
        pid::MAIN_LCGRPCONFIG => main_lc_grp_config: PDT_Generic01, ReadWrite;
        pid::SUB_LCGRPCONFIG => sub_lc_grp_config: PDT_Generic01, ReadWrite
    }
}

// ============================================================================
// IP Parameter Object (Object Type 11) - For KNXnet/IP devices
// ============================================================================

crate::define_interface_object! {
    /// IP Parameter Object - Object Type 11 (0x0B)
    ///
    /// Contains IP configuration for KNXnet/IP devices.
    /// This object is only present in KNXnet/IP devices.
    pub struct IpParameterObject: InterfaceObjectType::IPParameter {
        pid::PROJECT_INSTALLATION_ID => project_installation_id: PDT_UnsignedInt, ReadWrite;
        pid::CURRENT_IP_ASSIGNMENT_METHOD => current_ip_method: PDT_UnsignedChar, ReadOnly;
        pid::IP_ASSIGNMENT_METHOD => ip_method: PDT_UnsignedChar, ReadWrite;
        pid::IP_CAPABILITIES => ip_capabilities: PDT_UnsignedChar, ReadOnly;
        pid::FRIENDLY_NAME => friendly_name: PDT_Generic02, ReadWrite
    }
}

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
/// | 7 | Table Reference | PDT_UNSIGNED_LONG | RO | Pointer to table (legacy) |
/// | 23 | Table | varies | RW* | Direct table data access |
/// | 27 | MCB Table | PDT_GENERIC_08 | RO | Memory control block |
pub struct TableInterfaceObject<'a, T: LoadableTable, S: TableObjectSpec> {
    table: &'a RefCell<T>,
    _spec: PhantomData<S>,
}

impl<'a, T: LoadableTable, S: TableObjectSpec> TableInterfaceObject<'a, T, S> {
    /// Create a new table interface object wrapping an existing table
    pub fn new(table: &'a RefCell<T>) -> Self {
        Self {
            table,
            _spec: PhantomData,
        }
    }

    /// Get property descriptors for table objects
    fn property_descriptors() -> [PropertyDescriptor; 5] {
        [
            PropertyDescriptor::new(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 1, PropertyAccess::ReadOnly),
            PropertyDescriptor::new(pid::LOAD_STATE_CONTROL, PDT_UnsignedChar::ID, 1, PropertyAccess::ReadWrite),
            PropertyDescriptor::new(pid::TABLE_REFERENCE, 0x09, 1, PropertyAccess::ReadOnly), // PDT_UNSIGNED_LONG
            PropertyDescriptor::new(pid::TABLE, S::TABLE_PDT, 0, PropertyAccess::ReadWrite), // max_elements set dynamically
            PropertyDescriptor::new(pid::MCB_TABLE, 0x17, 1, PropertyAccess::ReadOnly), // PDT_GENERIC_08
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
        descriptors
            .iter()
            .enumerate()
            .find(|(_, d)| d.pid == pid)
            .map(|(i, d)| {
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
                if buf.len() < 2 {
                    return Err(PropertyError::BufferTooSmall);
                }
                let obj_type: u16 = S::OBJECT_TYPE.into();
                buf[0..2].copy_from_slice(&obj_type.to_be_bytes());
                Ok(2)
            }
            super::pid::LOAD_STATE_CONTROL => {
                if buf.is_empty() {
                    return Err(PropertyError::BufferTooSmall);
                }
                buf[0] = self.table.borrow().read_lsm()[0];
                Ok(1)
            }
            super::pid::TABLE_REFERENCE => {
                // Legacy property - return pointer value (we use 0 as placeholder)
                if buf.len() < 4 {
                    return Err(PropertyError::BufferTooSmall);
                }
                buf[0..4].copy_from_slice(&0u32.to_be_bytes());
                Ok(4)
            }
            super::pid::TABLE => {
                // Direct table data access - array property
                let table = self.table.borrow();
                let data = table.data_ref();

                // start_idx 0 means read element count
                if start_idx == 0 {
                    if buf.len() < 2 {
                        return Err(PropertyError::BufferTooSmall);
                    }
                    // Return current element count from first 2 bytes if has prefix
                    if S::HAS_COUNT_PREFIX && data.len() >= 2 {
                        buf[0..2].copy_from_slice(&data[0..2]);
                    } else {
                        let count = (data.len() / S::ENTRY_SIZE) as u16;
                        buf[0..2].copy_from_slice(&count.to_be_bytes());
                    }
                    return Ok(2);
                }

                // Calculate byte offset based on table format
                let byte_start = if S::HAS_COUNT_PREFIX {
                    // Data starts after 2-byte count, 1-indexed
                    2 + ((start_idx - 1) as usize) * S::ENTRY_SIZE
                } else {
                    (start_idx as usize) * S::ENTRY_SIZE
                };
                let byte_count = (count as usize) * S::ENTRY_SIZE;

                if byte_start >= data.len() {
                    return Err(PropertyError::InvalidStartIndex);
                }

                let available = data.len() - byte_start;
                let to_copy = byte_count.min(available).min(buf.len());

                buf[..to_copy].copy_from_slice(&data[byte_start..byte_start + to_copy]);
                Ok(to_copy)
            }
            super::pid::MCB_TABLE => {
                // Memory Control Block - 8 bytes
                if buf.len() < 8 {
                    return Err(PropertyError::BufferTooSmall);
                }
                buf[0..8].fill(0);
                Ok(8)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(&mut self, pid: u8, start_idx: u16, data: &[u8]) -> Result<(), PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE | super::pid::TABLE_REFERENCE | super::pid::MCB_TABLE => {
                Err(PropertyError::WriteNotAllowed)
            }
            super::pid::LOAD_STATE_CONTROL => {
                self.table.borrow_mut().write_lsm(data);
                Ok(())
            }
            super::pid::TABLE => {
                let mut table = self.table.borrow_mut();
                let table_data = table.data_ref_mut();

                // Calculate byte offset based on table format
                let byte_start = if start_idx == 0 {
                    0
                } else if S::HAS_COUNT_PREFIX {
                    2 + ((start_idx - 1) as usize) * S::ENTRY_SIZE
                } else {
                    (start_idx as usize) * S::ENTRY_SIZE
                };

                if byte_start + data.len() > table_data.len() {
                    return Err(PropertyError::InvalidStartIndex);
                }

                table_data[byte_start..byte_start + data.len()].copy_from_slice(data);
                Ok(())
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
                let data = table.data_ref();
                if S::HAS_COUNT_PREFIX && data.len() >= 2 {
                    Ok(u16::from_be_bytes([data[0], data[1]]))
                } else {
                    Ok((data.len() / S::ENTRY_SIZE) as u16)
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
    const TABLE_PDT: u8 = 0x11; // PDT_GENERIC_02
    const HAS_COUNT_PREFIX: bool = true;
}

/// Specification for Association Table Object (Type 2)
pub struct AssociationTableSpec;

impl TableObjectSpec for AssociationTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::AssociationTable;
    const ENTRY_SIZE: usize = 4; // TSAP + ASAP = 4 bytes
    const TABLE_PDT: u8 = 0x13; // PDT_GENERIC_04
    const HAS_COUNT_PREFIX: bool = true;
}

/// Specification for Group Object Table Object (Type 9)
pub struct GroupObjectTableSpec;

impl TableObjectSpec for GroupObjectTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::GroupObjectTable;
    const ENTRY_SIZE: usize = 2; // Type + Flags = 2 bytes
    const TABLE_PDT: u8 = 0x11; // PDT_GENERIC_02
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
        let obj = AddressTableObject::new(&addr_table);

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
        let mut obj = AddressTableObject::new(&addr_table);

        // Should start unloaded
        let mut buf = [0u8; 4];
        let len = obj.read_property(pid::LOAD_STATE_CONTROL, 1, 1, &mut buf).unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x00); // Unloaded

        // Start loading
        obj.write_property(pid::LOAD_STATE_CONTROL, 1, &[LoadEvent::StartLoading.into()]).unwrap();

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

        let obj = AddressTableObject::new(&addr_table);

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
        let obj = AddressTableObject::new(&addr_table);

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

        let obj = AssociationTableObject::new(&asso_table);

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

        let obj = GroupObjectTableObject::new(&co_table);

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
        let mut obj = AddressTableObject::new(&addr_table);

        // OBJECT_TYPE should not be writable
        let result = obj.write_property(pid::OBJECT_TYPE, 1, &[0x00, 0x00]);
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // TABLE_REFERENCE should not be writable
        let result = obj.write_property(pid::TABLE_REFERENCE, 1, &[0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // MCB_TABLE should not be writable
        let result = obj.write_property(pid::MCB_TABLE, 1, &[0x00; 8]);
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));
    }

    #[test]
    fn test_table_object_write_data() {
        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table);

        // Write count and entries via TABLE property
        obj.write_property(pid::TABLE, 0, &[0x00, 0x02]).unwrap(); // count = 2

        // Verify it was written
        let mut buf = [0u8; 10];
        let len = obj.read_property(pid::TABLE, 0, 1, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]);
    }
}
