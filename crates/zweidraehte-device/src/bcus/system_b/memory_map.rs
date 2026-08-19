//! Memory map implementation for System B devices.
//!
//! This module provides [`SystemBMemoryMap`], which maps memory addresses
//! to the device's tables for A_Memory_Read/Write services.

use crate::{
    HasSecurityMode,
    memory::{MemoryError, MemoryMap},
    objects::tables::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, TableMemory},
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::device::DeviceDescriptor;

/// Memory layout information for System B devices.
///
/// Describes the memory regions for each table based on their maximum sizes.
#[derive(Debug, Clone, Copy)]
pub struct MemoryLayout {
    /// Base address for all tables.
    pub base_address: u16,

    /// Address table offset from base.
    pub adt_offset: usize,
    /// Address table size in bytes.
    pub adt_size: usize,

    /// Association table offset from base.
    pub ast_offset: usize,
    /// Association table size in bytes.
    pub ast_size: usize,

    /// Group object table offset from base.
    pub cot_offset: usize,
    /// Group object table size in bytes.
    pub cot_size: usize,

    /// Application data offset from base.
    pub app_offset: usize,
    /// Application data size in bytes.
    pub app_size: usize,

    /// Total size of all mapped memory.
    pub total_size: usize,
}

impl MemoryLayout {
    /// Calculate memory layout for given table sizes.
    ///
    /// # Arguments
    ///
    /// - `base_address`: Starting address for memory-mapped tables
    /// - `max_addr`: Maximum group addresses (determines ADT size)
    /// - `max_asso`: Maximum associations (determines AST size)
    /// - `max_co`: Maximum communication objects (determines COT size)
    /// - `max_app`: Maximum application data size
    pub const fn calculate(base_address: u16, max_addr: usize, max_asso: usize, max_co: usize, max_app: usize) -> Self {
        // The per-table byte-width formulas live in one place: `table_sizes`
        // in this BCU's `storage` module (also the source of the `DeviceConfig`
        // const generics). Reuse it so the memory map and the persisted config
        // can never disagree on a table's on-wire size.
        let (adt_size, ast_size, cot_size) = super::storage::table_sizes(max_addr, max_asso, max_co);

        // Application data
        let app_size = max_app;

        Self {
            base_address,
            adt_offset: 0,
            adt_size,
            ast_offset: adt_size,
            ast_size,
            cot_offset: adt_size + ast_size,
            cot_size,
            app_offset: adt_size + ast_size + cot_size,
            app_size,
            total_size: adt_size + ast_size + cot_size + app_size,
        }
    }

    /// Calculate memory layout from a device descriptor.
    ///
    /// Shorthand for `calculate()` that extracts table capacities from the
    /// descriptor. `app_data_size` is typically `core::mem::size_of::<P>()`
    /// where `P` is the application parameter type.
    pub const fn from_descriptor(base_address: u16, device: &DeviceDescriptor, app_data_size: usize) -> Self {
        Self::calculate(
            base_address,
            device.max_address_table_entries as usize,
            device.max_association_table_entries as usize,
            device.max_com_objects as usize,
            app_data_size,
        )
    }

    /// Get the absolute address of the address table.
    pub const fn adt_address(&self) -> u16 {
        self.base_address + self.adt_offset as u16
    }

    /// Get the absolute address of the association table.
    pub const fn ast_address(&self) -> u16 {
        self.base_address + self.ast_offset as u16
    }

    /// Get the absolute address of the group object table.
    pub const fn cot_address(&self) -> u16 {
        self.base_address + self.cot_offset as u16
    }

    /// Get the absolute address of the application data.
    pub const fn app_address(&self) -> u16 {
        self.base_address + self.app_offset as u16
    }

    /// Get the end address (first address after mapped memory).
    pub const fn end_address(&self) -> u16 {
        self.base_address + self.total_size as u16
    }
}

/// Memory map for System B devices.
///
/// Maps memory addresses to the device's tables:
/// - Address Table (ADT)
/// - Association Table (AST)
/// - Group Object Table (COT)
/// - Application Program (APP)
///
/// # Memory Layout
///
/// Tables are laid out contiguously starting at the base address:
///
/// ```text
/// Base + 0x0000: Address Table
/// Base + ADT_SIZE: Association Table
/// Base + ADT_SIZE + AST_SIZE: Group Object Table
/// Base + ADT_SIZE + AST_SIZE + COT_SIZE: Application Data
/// ```
///
/// # Access Control
///
/// Currently all regions are read/write accessible at all access levels.
/// Future versions may implement per-region access control.
#[derive(Debug, Clone, Copy)]
pub struct SystemBMemoryMap {
    /// Memory layout describing table locations.
    layout: MemoryLayout,
}

impl SystemBMemoryMap {
    /// Default base address for memory-mapped tables.
    pub const DEFAULT_BASE_ADDRESS: u16 = 0x0100;

    /// Create a new memory map with the given layout.
    pub const fn new(layout: MemoryLayout) -> Self {
        Self { layout }
    }

    /// Create a new memory map for the given table sizes.
    ///
    /// Uses the default base address (0x0100).
    pub const fn for_device(max_addr: usize, max_asso: usize, max_co: usize, max_app: usize) -> Self {
        Self::new(MemoryLayout::calculate(Self::DEFAULT_BASE_ADDRESS, max_addr, max_asso, max_co, max_app))
    }

    /// Get the memory layout.
    pub const fn layout(&self) -> &MemoryLayout {
        &self.layout
    }
}

impl<Tables> MemoryMap<Tables> for SystemBMemoryMap
where
    Tables: HasAddressTable + HasAssociationTable + HasCommunicationObjectTable + HasApplication + HasSecurityMode,
{
    fn read(&self, tables: &Tables, address: u16, data: &mut [u8], _ctx: AccessContext) -> Result<usize, MemoryError> {
        let layout = &self.layout;

        // Check if address is within our mapped range
        if address < layout.base_address {
            return Err(MemoryError::NotAccessible);
        }

        let offset = (address - layout.base_address) as usize;

        // Check which region the address falls into
        // Note: We check against actual table size (data_ref().len()), not layout size,
        // because the layout might be configured for a larger maximum than the actual table.
        if offset < layout.ast_offset {
            // Address table region
            let table_offset = offset - layout.adt_offset;
            let table = tables.adt().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            table.read(table_offset, data);
            Ok(data.len())
        } else if offset < layout.cot_offset {
            // Association table region
            let table_offset = offset - layout.ast_offset;
            let table = tables.ast().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            table.read(table_offset, data);
            Ok(data.len())
        } else if offset < layout.app_offset {
            // Group object table region
            let table_offset = offset - layout.cot_offset;
            let table = tables.cot().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            table.read(table_offset, data);
            Ok(data.len())
        } else if offset < layout.total_size {
            // Application data region
            let table_offset = offset - layout.app_offset;
            let table = tables.app().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            table.read(table_offset, data);
            Ok(data.len())
        } else {
            Err(MemoryError::NotAccessible)
        }
    }

    fn write(&self, tables: &Tables, address: u16, data: &[u8], ctx: AccessContext) -> Result<usize, MemoryError> {
        // 03/05/01 §4.16.2 / §4.17.2 / §4.18.2: on devices supporting KNX
        // Secure, write access to the group address / association / group
        // object tables — "memory mapped or Property based" — is limited to
        // the Role "Tool"; other roles may only read. As an Access Policy
        // that is 3FF/00C (OPEN_OFF_TOOL_ON): everyone while Security Mode is
        // OFF, Tool only while it is ON. The legacy access-level scheme adds
        // no write restriction of its own (Vol 6 Annex A lists write level 3
        // for the System B table objects). The application/parameter region
        // is not covered by those clauses; we deliberately gate it under the
        // same policy because with Security Mode ON a plain parameter write
        // would otherwise bypass the secure download path.
        if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx, tables.security_mode_enabled()) {
            return Err(MemoryError::AccessDenied);
        }

        let layout = &self.layout;

        // Check if address is within our mapped range
        if address < layout.base_address {
            return Err(MemoryError::NotAccessible);
        }

        let offset = (address - layout.base_address) as usize;

        // Check which region the address falls into
        // Note: We check against actual table size (data_ref().len()), not layout size,
        // because the layout might be configured for a larger maximum than the actual table.
        if offset < layout.ast_offset {
            // Address table region
            let table_offset = offset - layout.adt_offset;
            let table = tables.adt().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            drop(table);
            tables.adt().borrow_mut().write(table_offset, data);
            Ok(data.len())
        } else if offset < layout.cot_offset {
            // Association table region
            let table_offset = offset - layout.ast_offset;
            let table = tables.ast().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            drop(table);
            tables.ast().borrow_mut().write(table_offset, data);
            Ok(data.len())
        } else if offset < layout.app_offset {
            // Group object table region
            let table_offset = offset - layout.cot_offset;
            let table = tables.cot().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            drop(table);
            tables.cot().borrow_mut().write(table_offset, data);
            Ok(data.len())
        } else if offset < layout.total_size {
            // Application data region
            let table_offset = offset - layout.app_offset;
            let table = tables.app().borrow();
            let actual_size = table.data_ref().len();
            if table_offset + data.len() > actual_size {
                return Err(MemoryError::NotAccessible);
            }
            drop(table);
            tables.app().borrow_mut().write(table_offset, data);
            Ok(data.len())
        } else {
            Err(MemoryError::NotAccessible)
        }
    }
}
