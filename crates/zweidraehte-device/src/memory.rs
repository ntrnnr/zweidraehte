//! Memory mapping for A_Memory_Read/Write services.
//!
//! This module provides the [`MemoryMap`] trait for defining how memory addresses
//! map to tables and other data regions in a KNX device.
//!
//! # Design
//!
//! The memory map is part of the [`StackDefinition`](crate::StackDefinition) and stored
//! in `Inner`. Users define their own tables struct (`MemoryTables`)
//! that contains whatever tables they need, and implement `MemoryMap` to dispatch
//! reads/writes to the appropriate tables.
//!
//! For group object communication, the stack requires the tables to implement
//! [`HasAddressTable`](crate::objects::tables::HasAddressTable),
//! [`HasAssociationTable`](crate::objects::tables::HasAssociationTable), and
//! [`HasCommunicationObjectTable`](crate::objects::tables::HasCommunicationObjectTable).

use zweidraehte_proto::AccessContext;
pub use zweidraehte_proto::memory::MemoryError;

// ============================================================================
// Memory Map
// ============================================================================

/// Trait for memory maps that dispatch reads/writes to tables.
///
/// Implementations define how memory addresses map to tables and other data regions.
/// The `Tables` type parameter is user-defined and can contain any set of tables
/// the device needs.
///
/// Addresses use `u32` because KNX extended-memory services carry a 24-bit
/// address and user-memory services carry a 20-bit address. Implementations
/// for mask families with a smaller address space must reject addresses outside
/// their mapped regions rather than truncate them.
///
/// The trait receives a reference to the user's tables container, allowing full
/// flexibility in the dispatch logic.
pub trait MemoryMap<Tables> {
    /// Read from memory at absolute address.
    ///
    /// The `ctx` parameter carries the caller's authorization context.
    /// Implementations can use this to restrict access to protected memory regions.
    ///
    /// Returns the number of bytes read, or an error if the address is not accessible
    /// or access is denied due to insufficient authorization.
    fn read(&self, tables: &Tables, address: u32, data: &mut [u8], ctx: AccessContext) -> Result<usize, MemoryError>;

    /// Write to memory at absolute address.
    ///
    /// The `ctx` parameter carries the caller's authorization context.
    /// Implementations can use this to restrict access to protected memory regions.
    ///
    /// Returns the number of bytes written, or an error if the address is not
    /// accessible, write-protected, or access is denied due to insufficient authorization.
    fn write(&self, tables: &Tables, address: u32, data: &[u8], ctx: AccessContext) -> Result<usize, MemoryError>;

    /// Whether a successful write changes persistent configuration.
    ///
    /// Profiles with volatile memory windows override this classification.
    fn is_persistent_write(&self, _address: u32, _length: usize) -> bool {
        true
    }

    /// Apply a management write and track only accepted configuration bytes.
    ///
    /// Empty, rejected and volatile writes do not advance the configuration
    /// revision, so polling or toggling programming mode is not download progress.
    fn write_config(&self, tables: &Tables, address: u32, data: &[u8], ctx: AccessContext) -> Result<usize, MemoryError>
    where
        Tables: crate::HasPersistence,
    {
        let written = self.write(tables, address, data, ctx)?;

        if written != 0 && self.is_persistent_write(address, written) {
            tables.mark_dirty();
        }

        Ok(written)
    }
}

// ============================================================================
// No Memory Map
// ============================================================================

/// A memory map with no mapped regions.
///
/// This is the default memory map that rejects all memory access.
/// Use this when you don't need memory services.
///
/// This implementation works with any `Tables` type since it doesn't
/// actually access any tables.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoMemoryMap;

impl<T> MemoryMap<T> for NoMemoryMap {
    fn read(&self, _tables: &T, _address: u32, _data: &mut [u8], _ctx: AccessContext) -> Result<usize, MemoryError> {
        Err(MemoryError::NotAccessible)
    }

    fn write(&self, _tables: &T, _address: u32, _data: &[u8], _ctx: AccessContext) -> Result<usize, MemoryError> {
        Err(MemoryError::NotAccessible)
    }
}
