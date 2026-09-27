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
    pub base_address: u32,

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
    pub const fn calculate(base_address: u32, max_addr: usize, max_asso: usize, max_co: usize, max_app: usize) -> Self {
        // The per-table byte-width formulas live in one place: `table_sizes`
        // in this BCU's `storage` module (also the source of the `DeviceConfig`
        // const generics). Reuse it so the memory map and the persisted config
        // can never disagree on a table's on-wire size.
        let (adt_size, ast_size, cot_size) = super::storage::table_sizes(max_addr, max_asso, max_co);

        // Application data
        let app_size = max_app;

        let total_size = adt_size + ast_size + cot_size + app_size;

        // A_MemoryExtended carries a 24-bit address. Reject a product
        // layout that could only be represented by wrapping that address.
        // Qualify these assertions because `zweidraehte-util` exposes
        // defmt's non-const `assert!` macro in firmware builds.
        core::assert!(base_address < 0x01_00_00_00, "memory base exceeds 24-bit address space");
        core::assert!(
            total_size <= (0x01_00_00_00 - base_address) as usize,
            "memory layout exceeds 24-bit address space"
        );

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
            total_size,
        }
    }

    /// Calculate memory layout from a device descriptor.
    ///
    /// Shorthand for `calculate()` that extracts table capacities from the
    /// descriptor. `app_data_size` is typically `core::mem::size_of::<P>()`
    /// where `P` is the application parameter type.
    pub const fn from_descriptor(base_address: u32, device: &DeviceDescriptor, app_data_size: usize) -> Self {
        Self::calculate(
            base_address,
            device.max_address_table_entries as usize,
            device.max_association_table_entries as usize,
            device.max_com_objects as usize,
            app_data_size,
        )
    }

    /// Get the absolute address of the address table.
    pub const fn adt_address(&self) -> u32 {
        self.base_address + self.adt_offset as u32
    }

    /// Get the absolute address of the association table.
    pub const fn ast_address(&self) -> u32 {
        self.base_address + self.ast_offset as u32
    }

    /// Get the absolute address of the group object table.
    pub const fn cot_address(&self) -> u32 {
        self.base_address + self.cot_offset as u32
    }

    /// Get the absolute address of the application data.
    pub const fn app_address(&self) -> u32 {
        self.base_address + self.app_offset as u32
    }

    /// Get the end address (first address after mapped memory).
    pub const fn end_address(&self) -> u32 {
        self.base_address + self.total_size as u32
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
/// Every region carries the Access Policy `3FF/04C`
/// ([`OPEN_OFF_TOOL_WRITES_ON`](AccessPolicy::OPEN_OFF_TOOL_WRITES_ON)),
/// checked before the region is resolved so a refusal is always
/// [`MemoryError::AccessDenied`]:
///
/// - **Tables.** AN193 v04 gives the group address, association and group
///   object table memory `3FF/0CC` "for whatever way (service)" they are
///   accessed, which lets Role A+C write. 03/05/01 §4.16.2, §4.17.2 and
///   §4.18.2 limit writes to the Tool, "memory mapped or Property based".
///   `04C` takes the read bits of the first and the write bits of the
///   second; the table objects' load state machines carry the same policy.
/// - **Application memory.** AN193 recommends `3FF/0CC`. We choose the
///   stricter `04C` as for the tables: a parameter write is part of the
///   same download.
///
/// The legacy access levels add no restriction: Annex A defines none for
/// System B memory.
#[derive(Debug, Clone, Copy)]
pub struct SystemBMemoryMap {
    /// Memory layout describing table locations.
    layout: MemoryLayout,
}

impl SystemBMemoryMap {
    /// Default base address for memory-mapped tables.
    pub const DEFAULT_BASE_ADDRESS: u32 = 0x0100;

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

    /// Whether `address` lies in the tables and application memory this
    /// map serves.
    pub const fn contains(&self, address: u32) -> bool {
        address >= self.layout.base_address && address < self.layout.end_address()
    }

    /// The offset of `address` from the base, once the policy lets `ctx`
    /// read it (or write it, if `write`).
    fn admit(&self, address: u32, ctx: &AccessContext, security_on: bool, write: bool) -> Result<usize, MemoryError> {
        if !self.contains(address) {
            return Err(MemoryError::NotAccessible);
        }

        let admitted =
            if write { MEMORY_POLICY.can_write(ctx, security_on) } else { MEMORY_POLICY.can_read(ctx, security_on) };
        if !admitted {
            return Err(MemoryError::AccessDenied);
        }

        usize::try_from(address - self.layout.base_address).map_err(|_| MemoryError::NotAccessible)
    }
}

/// The Access Policy of every region; see [`SystemBMemoryMap`].
const MEMORY_POLICY: AccessPolicy = AccessPolicy::OPEN_OFF_TOOL_WRITES_ON;

impl<Tables> MemoryMap<Tables> for SystemBMemoryMap
where
    Tables: HasAddressTable + HasAssociationTable + HasCommunicationObjectTable + HasApplication + HasSecurityMode,
{
    fn read(&self, tables: &Tables, address: u32, data: &mut [u8], ctx: AccessContext) -> Result<usize, MemoryError> {
        let layout = &self.layout;
        let offset = self.admit(address, &ctx, tables.security_mode_enabled(), false)?;

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

    fn write(&self, tables: &Tables, address: u32, data: &[u8], ctx: AccessContext) -> Result<usize, MemoryError> {
        let layout = &self.layout;
        let offset = self.admit(address, &ctx, tables.security_mode_enabled(), true)?;

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

#[cfg(test)]
mod tests {
    use super::MemoryLayout;

    #[test]
    fn layout_preserves_addresses_above_the_classic_memory_space() {
        let layout = MemoryLayout::calculate(0x01_0200, 2, 2, 2, 16);

        assert_eq!(layout.adt_address(), 0x01_0200);
        assert!(layout.ast_address() > 0x00_FFFF);
        assert!(layout.cot_address() > 0x00_FFFF);
        assert!(layout.app_address() > 0x00_FFFF);
        assert!(layout.end_address() > 0x00_FFFF);
    }
}
